use std::{
    fmt::Display,
    future::{ready, Ready},
    sync::Arc,
};

use actix_web::{
    body::{BoxBody, EitherBody},
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http, web, Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, Responder,
};
use futures_util::future::LocalBoxFuture;
use serde::Deserialize;

use crate::core::{
    config::Config,
    login::{self, Error as LoginError, WxLoginErr, WxLoginInfo, WxLoginOk, LOGIN_FAIL_MSG},
};

pub type WxLoginAuthResult = Result<WxLoginInfo, LoginError>;

pub struct WxLogin {
    cfg: Arc<Config>,
}

impl WxLogin {}

// Middleware factory is `Transform` trait
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S, ServiceRequest> for WxLogin
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static + Clone,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = WxLoginMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(WxLoginMiddleware {
            service,
            wx_login: login::WxLogin::new(self.cfg.clone()),
        }))
    }
}

#[derive(Clone)]
pub struct WxLoginMiddleware<S> {
    service: S,
    wx_login: login::WxLogin,
}

impl<S, B> Service<ServiceRequest> for WxLoginMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static + Clone,
    S::Future: 'static,
    B: 'static,
{
    // type Response = ServiceResponse<EitherBody<B, String>>;
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        #[derive(Deserialize)]
        struct LoginRequest {
            appid: String,
            code: String,
        }

        let myself = self.clone();

        Box::pin(async move {
            if req.uri().path() == "/login" {
                let LoginRequest { appid, code } = match match req.method() {
                    &http::Method::GET => web::Query::<LoginRequest>::extract(req.request())
                        .await
                        .map(|v| v.0)
                        .map_err(err_resp(400, "parse-get-params-fail", req.request())),
                    &http::Method::POST => {
                        let (request, payload) = req.parts_mut();
                        web::Json::<LoginRequest>::from_request(request, payload)
                            .await
                            .map(|v| v.0)
                            .map_err(err_resp(400, "parse-post-json-fail", request))
                    }
                    meth => Err(LoginError::from(meth.to_string())).map_err(err_resp(
                        500,
                        "unexpected-http-method",
                        req.request(),
                    )),
                } {
                    Ok(res) => res,
                    Err(err) => {
                        let resp = err.respond_to(req.request()).map_into_right_body();
                        return Ok(ServiceResponse::new(req.into_parts().0, resp));
                    }
                };
                myself
                    .wx_login
                    .handle_login(appid, code)
                    .await
                    .map(|v| v.respond_to(req.request()))
                    .or_else(|v| Ok(v.respond_to(req.request())))
                    .map(|v| ServiceResponse::new(req.into_parts().0, v.map_into_right_body()))
            } else {
                let header_stoken = req
                    .headers()
                    .get("WX-LOGIN-STOKEN")
                    .ok_or(LoginError::from("no WX-LOGIN-STOKEN header"));
                let stoken = header_stoken.and_then(|header_stoken| {
                    header_stoken
                        .to_str()
                        .map_err(|e| LoginError::from(e.to_string()))
                });
                let auth_info: WxLoginAuthResult = stoken.and_then(|stoken| {
                    let header_sig = req
                        .headers()
                        .get("WX-LOGIN-SIG")
                        .ok_or(LoginError::from("no WX-LOGIN-SIG header"));
                    let sig = header_sig.and_then(|header_sig| {
                        header_sig
                            .to_str()
                            .map_err(|e| LoginError::from(e.to_string()))
                    });
                    myself
                        .wx_login
                        .authenticate(stoken, &req.uri().to_string(), sig)
                });
                req.extensions_mut().insert(auth_info);
                myself
                    .service
                    .call(req)
                    .await
                    .map(|v| v.map_into_left_body())
            }
        })
    }
}

fn err_resp<'a, E: Display>(
    status: u16,
    code: &'a str,
    req: &'a HttpRequest,
) -> impl 'a + FnOnce(E) -> HttpResponse<BoxBody> {
    move |e| {
        WxLoginErr {
            status,
            code: code.into(),
            message: LOGIN_FAIL_MSG.into(),
            detail: e.to_string(),
        }
        .respond_to(req)
    }
}

impl Responder for WxLoginOk {
    type Body = BoxBody;
    fn respond_to(self, req: &HttpRequest) -> HttpResponse<Self::Body> {
        (web::Json(self), http::StatusCode::OK)
            .respond_to(req)
            .map_into_boxed_body()
    }
}
impl Responder for WxLoginErr {
    type Body = BoxBody;
    fn respond_to(self, req: &HttpRequest) -> HttpResponse<Self::Body> {
        let status = self.status;
        (web::Json(self), http::StatusCode::from_u16(status).unwrap())
            .respond_to(req)
            .map_into_boxed_body()
    }
}
