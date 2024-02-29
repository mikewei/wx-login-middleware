pub mod wx_login {
    pub use crate::core::config::{AppInfo, Config, ConfigBuilder};
    pub use crate::core::login::{WxLogin, WxLoginErr, WxLoginOk};
    #[cfg(feature = "axum")]
    pub use crate::axum::{WxLoginLayer, WxLoginService};
}
