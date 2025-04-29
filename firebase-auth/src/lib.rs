//! [Firebase](https://firebase.google.com) authentication layer for popular frameworks.
//!
//! Support:
//!
//! - [Axum](https://github.com/tokio-rs/axum)
//! - [Actix](https://github.com/actix/actix-web)
//!
//! ## Example:
//!
//! ### Actix
//!
//! ```rust no_run
//! use actix_web::{get, middleware::Logger, web::Data, App, HttpServer, Responder};
//! use firebase_auth::{FirebaseUser, FirebaseAuthBuilder};
//!
//! #[get("/hello")]
//! async fn greet(user: FirebaseUser) -> impl Responder {
//!     let email = user.email.unwrap_or("empty email".to_string());
//!     format!("Hello {}!", email)
//! }
//!
//! #[get("/public")]
//! async fn public() -> impl Responder {
//!     "ok"
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     let firebase_auth = FirebaseAuthBuilder::new("my-project-id")
//!         .build()
//!         .await;
//!
//!     let app_data = Data::new(firebase_auth);
//!
//!     HttpServer::new(move || {
//!         App::new()
//!             .wrap(Logger::default())
//!             .app_data(app_data.clone())
//!             .service(greet)
//!             .service(public)
//!     })
//!     .bind(("127.0.0.1", 8080))?
//!     .run()
//!     .await
//! }
//! ```
//!
//! ### Axum
//!
//! ```rust no_run
//! use axum::{routing::get, Router};
//! use firebase_auth::{FirebaseAuthState, FirebaseUser, FirebaseAuthBuilder};
//!
//! async fn greet(user: FirebaseUser) -> String {
//!     let email = user.email.unwrap_or("empty email".to_string());
//!     format!("hello {}", email)
//! }
//!
//! async fn public() -> &'static str {
//!     "ok"
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let firebase_auth = FirebaseAuthBuilder::new("my-project-id")
//!         .build()
//!         .await;
//!
//!     let app = Router::new()
//!         .route("/hello", get(greet))
//!         .route("/", get(public))
//!         .with_state(FirebaseAuthState::new(firebase_auth));
//!
//!
//!     let addr = "127.0.0.1:8080";
//!     let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
//!
//!     axum::serve(listener, app).await.unwrap();
//! }
//! ```
//!
//!Visit [README.md](https://github.com/trchopan/firebase-auth/) for more details.

mod firebase_auth;
pub use firebase_auth::FirebaseAuth;
pub use firebase_auth::FirebaseAuthBuilder;

mod structs;
pub use structs::{FirebaseUser, PublicKeysError, FirebaseProvider};

#[cfg(feature = "actix-web")]
mod actix_feature;

#[cfg(feature = "axum")]
mod axum_feature;

#[cfg(feature = "axum")]
pub use axum_feature::FirebaseAuthState;
