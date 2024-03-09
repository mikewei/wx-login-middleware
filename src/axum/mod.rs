use axum::{
    async_trait,
    extract::{FromRequest, FromRequestParts, Query, Request},
    http::{request::Parts, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use futures_util::{future::BoxFuture, TryFutureExt};
use serde::Deserialize;
use std::{
    convert::Infallible,
    fmt::Display,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

use crate::core::{
    config::{Config, ConfigBuilder},
    login::{Error, WxLogin, WxLoginErr, WxLoginInfo, WxLoginOk, AUTH_FAIL_MSG, LOGIN_FAIL_MSG},
};

pub type WxLoginAuthResult = Result<WxLoginInfo, Error>;

pub fn layer_with_env_var() -> WxLoginLayer {
    WxLoginLayer::new_with_env_var()
}

#[derive(Clone)]
pub struct WxLoginLayer {
    cfg: Arc<Config>,
}

impl WxLoginLayer {
    pub fn new_with_env_var() -> Self {
        Self::new(ConfigBuilder::new().with_env_var().build())
    }

    pub fn new(cfg: Config) -> Self {
        Self { cfg: Arc::new(cfg) }
    }
}

impl<S> Layer<S> for WxLoginLayer {
    type Service = WxLoginService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        WxLoginService {
            inner,
            wx_login: WxLogin::new(self.cfg.clone()),
        }
    }
}

#[derive(Clone)]
pub struct WxLoginService<S> {
    inner: S,
    wx_login: WxLogin,
}

impl<S> Service<Request> for WxLoginService<S>
where
    S: Service<Request, Response = Response> + Send + 'static + Clone,
    S::Future: Send + 'static,
    S::Error: Display,
{
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map(|r| r.or(Ok(())))
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        #[derive(Deserialize)]
        struct LoginRequest {
            appid: String,
            code: String,
        }

        let mut myself = self.clone();

        Box::pin(
            async move {
                if req.uri().path() == "/login" {
                    let LoginRequest { appid, code } = match req.method() {
                        &Method::GET => {
                            Query::<LoginRequest>::try_from_uri(req.uri())
                                .map_err(err_resp(400, "parse-get-params-fail"))?
                                .0
                        }
                        &Method::POST => {
                            Json::<LoginRequest>::from_request(req, &())
                                .await
                                .map_err(err_resp(400, "parse-post-json-fail"))?
                                .0
                        }
                        meth => Err(Error::from(meth.to_string()))
                            .map_err(err_resp(500, "unexpected-http-method"))?,
                    };
                    myself
                        .wx_login
                        .handle_login(appid, code)
                        .await
                        .map(|v| v.into_response())
                        .map_err(|v| v.into_response())
                } else {
                    let header_stoken = req
                        .headers()
                        .get("WX-LOGIN-STOKEN")
                        .ok_or(Error::from("no WX-LOGIN-STOKEN header"));
                    let stoken = header_stoken.and_then(|header_stoken| {
                        header_stoken
                            .to_str()
                            .map_err(|e| Error::from(e.to_string()))
                    });
                    let auth_info: WxLoginAuthResult = stoken.and_then(|stoken| {
                        let header_sig = req
                            .headers()
                            .get("WX-LOGIN-SIG")
                            .ok_or(Error::from("no WX-LOGIN-SIG header"));
                        let sig = header_sig.and_then(|header_sig| {
                            header_sig
                                .to_str()
                                .map_err(|e| Error::from(e.to_string()))
                        });
                        myself.wx_login.authenticate(stoken, &req.uri().to_string(), sig)
                    });
                    req.extensions_mut().insert(auth_info);
                    myself
                        .inner
                        .call(req)
                        .await
                        .map_err(err_resp(500, "inner-service-fail"))
                }
            }
            .or_else(|error_resp| async move { Ok(error_resp) }),
        )
    }
}

fn err_resp<E: Display>(status: u16, code: &str) -> impl '_ + FnOnce(E) -> Response {
    move |e| {
        WxLoginErr {
            status,
            code: code.into(),
            message: LOGIN_FAIL_MSG.into(),
            detail: e.to_string(),
        }
        .into_response()
    }
}

pub type WxLoginInfoRejection = WxLoginErr;

#[async_trait]
impl<S> FromRequestParts<S> for WxLoginInfo
where
    S: Send + Sync,
{
    type Rejection = WxLoginInfoRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<WxLoginAuthResult>() {
            Some(Ok(login_info)) => Ok(login_info.clone()),
            Some(Err(err)) => Err(WxLoginErr {
                status: 401,
                code: "auth-login-session-fail".into(),
                message: AUTH_FAIL_MSG.into(),
                detail: err.to_string(),
            }),
            None => Err(WxLoginErr {
                status: 500,
                code: "login-session-lost".into(),
                message: AUTH_FAIL_MSG.into(),
                detail: "".into(),
            }),
        }
    }
}

impl IntoResponse for WxLoginOk {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}
impl IntoResponse for WxLoginErr {
    fn into_response(self) -> Response {
        (StatusCode::from_u16(self.status).unwrap(), Json(self)).into_response()
    }
}
