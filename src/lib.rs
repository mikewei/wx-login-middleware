//! A Rust library that provides WeChat mini-program login and authentication functionalities
//! in the form of middleware of popular web-frameworks, making it convenient to use.
//!
//! ## Examples
//!
//! ### Axum
//!
//! ```no_run
//! # tokio_test::block_on(async {
//! use axum::{routing::get, Router};
//! use wx_login_middleware::preclude::*;
//! 
//! let app = Router::new()
//!     .route("/", get(root))
//!     // add the layer of wx_login_middleware for login and authentication
//!     // we use default config with app-info from environment variables 
//!     // (e.g. WX_APP_"TheAppID"="TheAppSecret")
//!     .layer(wx_login::layer_with_env_var());
//! 
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//! axum::serve(listener, app).await.unwrap();
//! 
//! # async fn root() -> &'static str { "" }
//! # })
//! ```
//!
pub mod preclude;
pub use preclude::*;

pub(crate) mod core;

#[cfg(feature = "axum")]
pub(crate) mod axum;

#[cfg(feature = "actix-web")]
pub(crate) mod actix_web;
