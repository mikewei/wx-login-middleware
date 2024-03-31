# wx-login-middleware

A Rust library that provides WeChat mini-program login and authentication functionalities
in the form of middleware of popular web-frameworks, making it convenient to use.

### Examples

#### Axum

```rust
use axum::{routing::get, Router};
use wx_login_middleware::preclude::*;

let app = Router::new()
    // `GET /auth` goes to `auth` which require login authendication
    .route("/auth", get(auth))
    // add the layer of wx_login_middleware for login and authentication
    // by default the login API is `GET|POST /login`
    // here we use default config of app-info from environment variables
    // (e.g. WX_APP_"TheAppID"="TheAppSecret")
    .layer(wx_login::axum::layer_with_env_var());

let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
axum::serve(listener, app).await.unwrap();

// use WxLoginInfo extractor to check authentication result
async fn auth(login_info: wx_login::WxLoginInfo) -> String {
   format!("Hello, {}!", login_info.openid)
}
```

#### Actix-Web

```rust
use actix_web::{get, App, Responder, HttpServer, HttpResponse};
use wx_login_middleware::preclude::*;

async fn main() -> std::io::Result<()> {
   HttpServer::new(|| {
       App::new()
           // add the middleware for login and authentication
           // by default the login API is `GET|POST /login`
           // here we use config of app-info from environment variables
           // (e.g. WX_APP_"TheAppID"="TheAppSecret")
           .wrap(wx_login::actix_web::middleware_with_env_var())
           // `GET /auth` require login authendication
           .service(auth)
   }).bind(("127.0.0.1", 8080))?.run().await
}

#[get("/auth")]
// use WxLoginInfo extractor to check authentication result
async fn auth(login_info: wx_login::WxLoginInfo) -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, {}!", login_info.openid))
}
```

### Protocol

#### Login

Use GET or POST /login (which is the default path and can be customized with wx_login::Config).

**Request (GET)**

```shell
curl --url "https://<host>/login?appid=<your_app_id>&code=<code_from_wxlogin>"
```

**Request (POST)**

```shell
curl --request POST --url "https://<host>/login" --data '{"appid": "<your_app_id>", "code": "<code_from_wxlogin>"}'
```

**Response**

Success (StatusCode 200):

```json
{
  "openid": "<the_login_open_id>",
  "stoken": "<session_token_for_subsequent_request>",
  "skey": "<session_key_for_making_signature>",
}
```

Fail (StatusCode 400|401|500):

```json
{
  "status": <status_code>,
  "code": "<short_error_code>",
  "message": "<error_message_for_user>",
  "detail": "<debug_message_for_developer>",
}
```

#### Authentication

After login client can attach header *WX-LOGIN-STOKEN* and *WX-LOGIN-SIG* with subsequent request for authentication.

- *WX-LOGIN-STOKEN*: the session-token from login response

- *WX-LOGIN-SIG*: the signature of request uri (path+params), calculated as SG1:ts:nonce:sha1(uri:ts:nonce:skey)

```shell
curl --header "WX-LOGIN-STOKEN=<stoken>" --header "WX-LOGIN-SIG=<sig>" --url "https://<host>/someapi"
```

If the api server requires authentication (usually by using WxLoginInfo extractor) and the authentication failed,
the error response (StatusCode 401|500) will be returned:

```json
{
  "status": <status_code>,
  "code": "<short_error_code>",
  "message": "<error_message_for_user>",
  "detail": "<debug_message_for_developer>",
}
```

#### Frontend

One can find frontend javascript sample code in repo *frontend* directory for reference.


License: MIT
