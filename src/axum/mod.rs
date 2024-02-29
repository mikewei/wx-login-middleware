use axum::{
    extract::{FromRequest, Query, Request},
    http::{Method, StatusCode},
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
    login::{WxLogin, WxLoginErr, WxLoginOk, LOGIN_FAIL_MSG},
};

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
            wx_login: Arc::new(WxLogin::new(self.cfg.clone())),
        }
    }
}

#[derive(Clone)]
pub struct WxLoginService<S> {
    inner: S,
    wx_login: Arc<WxLogin>,
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

    fn call(&mut self, req: Request) -> Self::Future {
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
                                .map_err(err_resp("parse-get-params-fail"))?
                                .0
                        }
                        &Method::POST => {
                            Json::<LoginRequest>::from_request(req, &())
                                .await
                                .map_err(err_resp("parse-post-json-fail"))?
                                .0
                        }
                        meth => Err(axum::Error::new(meth.to_string()))
                            .map_err(err_resp("unexpected-http-method"))?,
                    };
                    myself
                        .wx_login
                        .handle_login(appid, code)
                        .await
                        .map(|v| v.into_response())
                        .map_err(|v| v.into_response())
                } else {
                    myself
                        .inner
                        .call(req)
                        .await
                        .map_err(err_resp("inner-service-fail"))
                }
            }
            .or_else(|err_resp| async move { Ok(err_resp) }),
        )
    }
}

fn err_resp<E: Display>(code: &str) -> impl '_ + FnOnce(E) -> Response {
    move |e| {
        WxLoginErr {
            status: 500,
            code: code.into(),
            message: LOGIN_FAIL_MSG.into(),
            detail: e.to_string(),
        }
        .into_response()
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
