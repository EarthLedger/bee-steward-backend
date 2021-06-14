#[macro_use]
extern crate diesel;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate redis_async;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate validator_derive;
#[macro_use]
extern crate log;

use actix_rt::{spawn, time};
use std::time::Duration;

use crate::models::node_json::update_node_status;
use crate::server::server;

mod auth;
mod cache;
mod config;
mod database;
mod errors;
mod extractors;
pub mod handlers;
mod helpers;
mod middleware;
mod models;
mod response;
mod routes;
mod schema;
mod server;
mod state;
mod tests;
mod validate;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // task process
    spawn(async move {
        let mut interval = time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            // do something
            match update_node_status() {
                Ok(()) => println!("ok"),
                Err(e) => println!("err: {:?}", e),
            }
        }
    });

    server().await
}
