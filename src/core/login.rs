use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::config::Config;

pub(crate) const LOGIN_FAIL_MSG: &str = "登录验证失败";

#[derive(Serialize)]
pub struct WxLoginOk {
    pub openid: String,
    pub st: String,
    pub sk: String,
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
        let client = reqwest::Client::new();
        let url = "https://api.weixin.qq.com/sns/jscode2session";
        let code2sess_req = Code2SessionRequest::from(&self.cfg, appid, code);
        let res = client
            .get(url)
            .query(&code2sess_req)
            .send()
            .await
            .map_err(|e| WxLoginErr {
                status: 500,
                code: "jscode2session-call-fail".into(),
                message: LOGIN_FAIL_MSG.into(),
                detail: e.to_string(),
            })?;
        let code2sess_res = res
            .json::<Code2SessionResponse>()
            .await
            .map_err(|e| WxLoginErr {
                status: 500,
                code: "jscode2session-resp-decode-fail".into(),
                message: LOGIN_FAIL_MSG.into(),
                detail: e.to_string(),
            })?;
        tracing::info!(?code2sess_res);
        Ok(WxLoginOk {
            openid: code2sess_res.openid,
            st: "".into(),
            sk: "".into(),
        })
    }
}

#[derive(Serialize)]
struct Code2SessionRequest {
    appid: String,
    secret: String,
    js_code: String,
    grant_type: String,
}

impl Code2SessionRequest {
    fn from(cfg: &Config, appid: String, code: String) -> Self {
        Self {
            appid: appid.clone(),
            secret: cfg.app_map.get(&appid).unwrap().secret.clone(),
            js_code: code,
            grant_type: "authorization_code".into(),
        }
    }
}

#[derive(Deserialize, Debug)]
struct Code2SessionResponse {
    session_key: String,
    openid: String,
    unionid: Option<String>,
}
