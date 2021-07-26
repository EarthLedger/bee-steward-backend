//! Database-related functions
use crate::config::{Config, CONFIG};
use crate::errors::ApiError;
use actix_web::web;
use sqlx::mysql::MySqlPool;

pub async fn init_pool(config: Config) -> Result<MySqlPool, ApiError::PoolError> {
    let database_url = if config.db_env == "test" {
        config.database_test_url
    } else {
        config.database_url
    };

    let pool = MySqlPool::connect(&database_url).await?;
    Ok(pool)
}

pub fn add_pool(cfg: &mut web::ServiceConfig) {
    let pool = init_pool(CONFIG.clone()).expect("Failed to create connection pool");
    cfg.data(pool);
}
