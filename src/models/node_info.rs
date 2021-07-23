use crate::database::PoolType;
use crate::errors::ApiError;
use crate::schema::node_infos;
use chrono::NaiveDateTime;
use diesel::prelude::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Queryable, Identifiable, Insertable)]
#[primary_key(addr)]
pub struct NodeInfo {
    pub addr: String,
    pub cheque_book_addr: String,
    pub run_status: i32,
    pub connection: i32,
    pub depth: i32,
    pub cheque_received_count: i32,
    pub cheque_received_balance: String,
    pub peer_max_postive_balance: String,
    pub node_bzz: String,
    pub node_xdai: String,
    pub cheque_bzz: String,
    pub created_by: String,
    pub created_at: NaiveDateTime,
    pub updated_by: String,
    pub updated_at: NaiveDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewNodeInfo {
    pub addr: String,
    pub cheque_book_addr: String,
    pub run_status: i32,
    pub connection: i32,
    pub depth: i32,
    pub cheque_received_count: i32,
    pub cheque_received_balance: String,
    pub peer_max_postive_balance: String,
    pub node_bzz: String,
    pub node_xdai: String,
    pub cheque_bzz: String,
    pub created_by: String,
    pub updated_by: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, AsChangeset)]
#[table_name = "node_infos"]
pub struct UpdateNodeInfo {
    pub addr: String,
    pub cheque_book_addr: String,
    pub run_status: i32,
    pub connection: i32,
    pub depth: i32,
    pub cheque_received_count: i32,
    pub cheque_received_balance: String,
    pub peer_max_postive_balance: String,
    pub node_bzz: String,
    pub node_xdai: String,
    pub cheque_bzz: String,
    pub updated_by: String,
}

pub fn create_node_info(pool: &PoolType, new_node_info: &NodeInfo) -> Result<NodeInfo, ApiError> {
    use crate::schema::node_infos::dsl::node_infos;

    let conn = pool.get()?;

    diesel::replace_into(node_infos)
        .values(new_node_info)
        .execute(&conn)?;
    Ok(new_node_info.clone())
}

pub fn update_node_info(
    pool: &PoolType,
    update_node_info: &UpdateNodeInfo,
) -> Result<NodeInfo, ApiError> {
    use crate::schema::node_infos::dsl::{addr, node_infos};

    let conn = pool.get()?;
    diesel::update(node_infos)
        .filter(addr.eq(update_node_info.addr.clone()))
        .set(update_node_info)
        .execute(&conn)?;

    get_by_addr(&pool, &update_node_info.addr)
}

pub fn get_by_addr(pool: &PoolType, node_addr: &str) -> Result<NodeInfo, ApiError> {
    use crate::schema::node_infos::dsl::{addr, node_infos};

    let not_found = format!("Node {} not found", node_addr);
    let conn = pool.get()?;
    let node = node_infos
        .filter(addr.eq(node_addr.to_string()))
        .first::<NodeInfo>(&conn)
        .map_err(|_| ApiError::NotFound(not_found))?;
    Ok(node)
}
