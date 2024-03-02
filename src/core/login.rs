use crate::core::config::Config;
use crate::core::security::Authority;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, sync::Arc};
use tiny_crypto::encoding::{Encoder, BASE64};

pub use crate::core::security::Error;
use crate::core::security::ServerSession;

pub(crate) const LOGIN_FAIL_MSG: &str = "登录验证失败";

#[derive(Serialize)]
pub struct WxLoginOk {
    pub openid: String,
    pub stoken: String,
    pub skey: String,
}

#[derive(Serialize)]
pub struct WxLoginErr {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct WxLogin {
    cfg: Arc<Config>,
}

impl WxLogin {
    pub fn new(cfg: Arc<Config>) -> Self {
        Self { cfg }
    }

    pub async fn handle_login(&self, appid: String, code: String) -> Result<WxLoginOk, WxLoginErr> {
        let app_info = self.cfg.app_map.get(&appid).ok_or(WxLoginErr {
            status: 401,
            code: "appid-not-found".into(),
            message: LOGIN_FAIL_MSG.into(),
            detail: "".into(),
        })?;
        let client = reqwest::Client::new();
        let url = "https://api.weixin.qq.com/sns/jscode2session";
        let code2sess_req =
            proto::Code2SessionRequest::from(appid.clone(), app_info.secret.clone(), code);
        let res = client
            .get(url)
            .query(&code2sess_req)
            .send()
            .await
            .map_err(err_resp(500, "jscode2session-call-fail"))?;
        let code2sess_res = res
            .json::<proto::Code2SessionResponse>()
            .await
            .map_err(err_resp(401, "jscode2session-resp-fail"))?;
        tracing::info!(?code2sess_res);
        let openid = code2sess_res.openid;
        let session_key: [u8; 16] = BASE64
            .from_text(&code2sess_res.session_key)
            .map_err(err_resp(500, "session-key-invalid-base64"))?
            .try_into()
            .map_err(|v: Vec<u8>| format!("unexpected key len: {}", v.len()))
            .map_err(err_resp(500, "session-key-invalid-base64"))?;
        let authority = Authority::new(app_info);
        let client_sess = authority.make_client_session(&openid, &session_key);
        Ok(WxLoginOk {
            openid: openid.clone(),
            stoken: [appid, openid, client_sess.sess_token].join("::"),
            skey: client_sess.sess_key,
        })
    }

    pub fn authenticate(&self, stoken: &str) -> Result<ServerSession, Error> {
        let (appid, openid, token_str) = stoken.split("::").next_tuple().unwrap();
        let app_info = self.cfg.app_map.get(appid).ok_or("appid not found")?;
        let authority = Authority::new(app_info);
        authority.auth_client_session(openid, token_str, None)
    }
}

fn err_resp<E: Display>(status: u16, code: &str) -> impl '_ + FnOnce(E) -> WxLoginErr {
    move |e| WxLoginErr {
        status,
        code: code.into(),
        message: LOGIN_FAIL_MSG.into(),
        detail: e.to_string(),
    }
}

mod proto {
    use super::*;

    #[derive(Serialize)]
    pub(crate) struct Code2SessionRequest {
        appid: String,
        secret: String,
        js_code: String,
        grant_type: String,
    }

    impl Code2SessionRequest {
        pub(crate) fn from(appid: String, secret: String, code: String) -> Self {
            Self {
                appid,
                secret,
                js_code: code,
                grant_type: "authorization_code".into(),
            }
        }
    }

    #[derive(Deserialize, Debug)]
    pub(crate) struct Code2SessionResponse {
        pub(crate) session_key: String,
        pub(crate) openid: String,
        pub(crate) _unionid: Option<String>,
    }
}
