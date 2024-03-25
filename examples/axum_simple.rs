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
        // `GET /auth` goes to `auth` which require login authendication
        .route("/auth", get(auth))
        // add the layer of wx_login_middleware for login and authentication
        // we use default config with app-info from environment variables
        // (e.g. WX_APP_"TheAppID"="TheAppSecret")
        .layer(wx_login::axum::layer_with_env_var());

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello world!"
}

// use WxLoginInfo extractor to check authentication result
async fn auth(login_info: wx_login::WxLoginInfo) -> String {
    format!("Hello, {}!", login_info.openid)
}
