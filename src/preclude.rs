pub mod wx_login {
    #[cfg(feature = "axum")]
    pub mod axum {
        pub use crate::axum::{
            layer_with_env_var, WxLoginAuthResult, WxLoginInfoRejection, WxLoginLayer, WxLoginService,
        };
    }
    #[cfg(feature = "axum")]
    pub mod actix_web {
        pub use crate::actix_web::{
            middleware_with_env_var, WxLoginMiddleware, WxLoginMiddlewareService,
        };
    }
    pub use crate::core::config::{AppInfo, Config, ConfigBuilder};
    pub use crate::core::login::{Error, WxLogin, WxLoginErr, WxLoginInfo, WxLoginOk};
}
