use std::collections::HashMap;

use crate::core::security::secret_utils::SecretString;

#[derive(Default, Debug, Clone)]
pub struct AppInfo {
    pub(crate) appid: String,
    pub(crate) secret: SecretString,
}
impl AppInfo {
    pub fn from(appid: String, secret: String) -> Self {
        Self {
            appid,
            secret: SecretString(secret),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub(crate) app_map: HashMap<String, AppInfo>,
    pub(crate) login_path: String,
    pub(crate) auth_sig: bool,
    pub(crate) sig_valid_secs: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            app_map: Default::default(),
            login_path: "/login".into(),
            auth_sig: true,
            sig_valid_secs: 600,
        }
    }
}
impl Config {
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }
}

#[derive(Default)]
pub struct ConfigBuilder {
    cfg: Config,
}
impl ConfigBuilder {
    pub fn new() -> Self {
        Default::default()
    }
    fn add_app_info(&mut self, app_info: AppInfo) {
        self.cfg.app_map.insert(app_info.appid.clone(), app_info);
    }
    pub fn with_app_info(mut self, app_info: AppInfo) -> Self {
        self.add_app_info(app_info);
        self
    }
    pub fn with_env_var(mut self) -> Self {
        const PREFIX: &str = "WX_APP_";
        std::env::vars()
            .filter(|(k, _)| k.starts_with(PREFIX))
            .for_each(|(k, v)| {
                self.add_app_info(AppInfo::from(k[PREFIX.len()..].into(), v));
            });
        self
    }
    pub fn with_login_path(mut self, path: &str) -> Self {
        self.cfg.login_path = path.into();
        self
    }
    pub fn with_auth_sig(mut self, on: bool) -> Self {
        self.cfg.auth_sig = on;
        self
    }
    pub fn with_sig_valid_secs(mut self, secs: u64) -> Self {
        self.cfg.sig_valid_secs = secs;
        self
    }
    pub fn build(self) -> Config {
        tracing::info!("use {:?}", self.cfg);
        self.cfg
    }
}
