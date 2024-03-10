use axum::{routing::get, Router};
use wx_login_middleware::preclude::*;

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        // add the layer of wx_login_middleware for login and authentication
        // we use default config with environment variable of app info
        .layer(wx_login::layer_with_env_var());

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// basic handler that responds with a static string
// use WxLoginInfo extractor to check authentication result
async fn root(login_info: wx_login::WxLoginInfo) -> String {
    format!("Hello, {}!", login_info.openid)
}
