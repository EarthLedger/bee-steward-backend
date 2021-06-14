use crate::database::PoolType;
use crate::errors::ApiError;
use crate::handlers::node::{NodeResponse, NodeResponses};
use crate::models::node_json::{get_node_info, NodeInfo};
use crate::schema::nodes;
use crate::schema::servers;
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Queryable, Identifiable, Insertable)]
#[primary_key(addr)]
pub struct Node {
    pub addr: String,
    pub server_id: String,
    pub server_idx: i32,
    pub customer: Option<String>,
    pub sub: Option<String>,
    pub created_by: String,
    pub created_at: NaiveDateTime,
    pub updated_by: String,
    pub updated_at: NaiveDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewNode {
    pub addr: String,
    pub server_id: String,
    pub server_idx: i32,
    pub customer: Option<String>,
    pub sub: Option<String>,
    pub created_by: String,
    pub updated_by: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, AsChangeset)]
#[table_name = "nodes"]
pub struct UpdateNode {
    pub addr: String,
    pub server_id: String,
    pub server_idx: i32,
    pub customer: Option<String>,
    pub sub: Option<String>,
    pub updated_by: String,
}

pub fn get_all(pool: &PoolType) -> Result<Vec<Node>, ApiError> {
    use crate::schema::nodes::dsl::nodes;

    let conn = pool.get()?;
    let all_nodes = nodes.load(&conn)?;

    Ok(all_nodes)
}

pub fn get_by_addr(pool: &PoolType, node_addr: &str) -> Result<Node, ApiError> {
    use crate::schema::nodes::dsl::{addr, nodes};

    let not_found = format!("Node {} not found", node_addr);
    let conn = pool.get()?;
    let node = nodes
        .filter(addr.eq(node_addr.to_string()))
        .first::<Node>(&conn)
        .map_err(|_| ApiError::NotFound(not_found))?;

    Ok(node)
}

pub fn get_by_customer(pool: &PoolType, customer_id: &str) -> Result<NodeResponses, ApiError> {
    use crate::schema::nodes::dsl::{customer, nodes};

    let conn = pool.get()?;
    let filter_nodes = nodes
        .filter(customer.eq(customer_id.to_string()))
        .load::<Node>(&conn)
        .map_err(|e| {
            println!("?{}", e);
            ApiError::PoolError(e.to_string())
        })?;
    // append node status from json store
    let mut res: NodeResponses = vec![];
    for node in filter_nodes {
        res.push(NodeResponse {
            info: get_node_info(&node.addr)?,
            node,
        })
    }

    Ok(res)
}

pub fn get_by_sub(pool: &PoolType, sub_id: &str) -> Result<NodeResponses, ApiError> {
    use crate::schema::nodes::dsl::{nodes, sub};

    let conn = pool.get()?;
    let filter_nodes = nodes
        .filter(sub.eq(sub_id.to_string()))
        .load::<Node>(&conn)
        .map_err(|e| {
            println!("?{}", e);
            ApiError::PoolError(e.to_string())
        })?;
    let mut res: NodeResponses = vec![];
    for node in filter_nodes {
        res.push(NodeResponse {
            info: get_node_info(&node.addr)?,
            node,
        })
    }

    Ok(res)
}

pub fn create_node(pool: &PoolType, new_node: &Node) -> Result<Node, ApiError> {
    use crate::schema::nodes::dsl::nodes;

    let conn = pool.get()?;
    diesel::insert_into(nodes).values(new_node).execute(&conn)?;
    Ok(new_node.clone().into())
}

pub fn update_node(pool: &PoolType, update_node: &UpdateNode) -> Result<Node, ApiError> {
    use crate::schema::nodes::dsl::{addr, nodes};

    let conn = pool.get()?;
    diesel::update(nodes)
        .filter(addr.eq(update_node.addr.clone()))
        .set(update_node)
        .execute(&conn)?;

    get_by_addr(&pool, &update_node.addr)
}

impl From<NewNode> for Node {
    fn from(node: NewNode) -> Self {
        Node {
            addr: node.addr,
            server_id: node.server_id,
            server_idx: node.server_idx,
            customer: node.customer,
            sub: node.sub,
            created_by: node.created_by,
            created_at: Utc::now().naive_utc(),
            updated_by: node.updated_by,
            updated_at: Utc::now().naive_utc(),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tests::helpers::tests::get_pool;
    use chrono::Utc;

    pub fn get_all_nodes() -> Result<Vec<Node>, ApiError> {
        let pool = get_pool();
        get_all(&pool)
    }

    pub fn create_new_test_node() -> Result<Node, ApiError> {
        let pool = get_pool();
        let new_node = NewNode {
            addr: format!("{}", Utc::now()).into(),
            server_id: "abc".to_string(),
            server_idx: 0,
            customer: Some("xxxxxx-xxxxxx-0001".to_string()),
            sub: Some("sub".to_string()),
            created_by: "aaaaaa".to_string(),
            updated_by: "aaaaaa".to_string(),
        };

        create_node(&pool, &new_node.into())
    }

    #[test]
    fn it_create_node() {
        let result = create_new_test_node();
        assert!(result.is_ok());
    }

    #[test]
    fn it_gets_nodes() {
        let nodes = get_all_nodes();
        println!("nodes: {:?}", nodes);
        assert!(nodes.is_ok());
    }

    #[test]
    fn it_gets_by_customer() {
        let pool = get_pool();
        let nodes = get_by_customer(&pool, "xxxxxx-xxxxxx-0001".into());
        println!("nodes: {:?}", nodes);
        assert!(nodes.is_ok());
    }

    #[test]
    fn it_gets_by_sub() {
        let pool = get_pool();
        let nodes = get_by_sub(&pool, "sub".into());
        println!("nodes: {:?}", nodes);
        assert!(nodes.is_ok());
    }

    #[test]
    fn it_gets_by_addr() {
        let pool = get_pool();

        let node = create_new_test_node().unwrap();

        let find_result = get_by_addr(&pool, &node.addr).unwrap();
        assert_eq!(find_result.addr, node.addr);
    }

    #[test]
    fn it_update_node() {
        // create a new node
        let node = create_new_test_node().unwrap();

        let updated_node = UpdateNode {
            addr: node.addr,
            server_id: node.server_id,
            server_idx: node.server_idx,
            customer: node.customer,
            sub: Some("newsub".to_string()),
            updated_by: node.updated_by,
        };

        let result = update_node(&get_pool(), &updated_node).unwrap();
        assert_eq!(result.sub, Some("newsub".to_string()));
    }
}
