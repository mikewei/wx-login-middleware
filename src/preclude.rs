pub mod wx_login {
    #[cfg(feature = "axum")]
    pub use crate::axum::{
        layer_with_env_var, WxLoginAuthResult, WxLoginInfoRejection, WxLoginLayer, WxLoginService,
    };
    pub use crate::core::config::{AppInfo, Config, ConfigBuilder};
    pub use crate::core::login::{Error, WxLogin, WxLoginErr, WxLoginInfo, WxLoginOk};
}
