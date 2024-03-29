use actix_web::{get, App, HttpResponse, HttpServer, Responder};
use wx_login_middleware::preclude::*;

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[get("/auth")]
// use WxLoginInfo extractor to check authentication result
async fn auth(login_info: wx_login::WxLoginInfo) -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, {}!", login_info.openid))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();
    HttpServer::new(|| {
        App::new()
            // add the middleware for login and authentication
            // by default the login API is `GET|POST /login`
            // here we use config of app-info from environment variables
            // (e.g. WX_APP_"TheAppID"="TheAppSecret")
            .wrap(wx_login::actix_web::middleware_with_env_var())
            .service(hello)
            // `GET /auth` require login authendication
            .service(auth)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}