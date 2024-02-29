use std::collections::HashMap;

#[derive(Default, Debug, Clone)]
pub struct AppInfo {
    pub(crate) appid: String,
    pub(crate) secret: String,
}
impl AppInfo {
    pub fn from(appid: String, secret: String) -> Self {
        Self { appid, secret }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Config {
    // pub appid: String,
    // pub secret: String,
    pub(crate) app_map: HashMap<String, AppInfo>,
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
            .for_each(|(k, v)| { self.add_app_info(AppInfo::from(k[PREFIX.len()..].into(), v)); });
        self
    }
    pub fn build(self) -> Config {
        tracing::info!("build {:?}", self.cfg);
        self.cfg
    }
}