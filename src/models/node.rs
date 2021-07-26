use crate::database::PoolType;
use crate::errors::ApiError;
use crate::handlers::node::{
    AssignCustomerNodesRequest, AssignSubNodesRequest, NodeResponse, NodeResponses,
    QueryOptionRequest,
};
use crate::handlers::user::UserResponse;
use crate::models::node_info::NodeInfo;
use crate::models::node_json::{get_node_info, load_by_server_cluster};
use crate::models::user::{find, AuthUser, Role};
use crate::response::DEFAULT_PAGE_SIZE;
use crate::schema::nodes;
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use std::str::FromStr;

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Queryable,
    Identifiable,
    Insertable,
    Associations,
)]
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

#[derive(Clone, Debug, Serialize, Deserialize, AsChangeset)]
#[table_name = "nodes"]
pub struct UpdateNodeSub {
    pub sub: Option<String>,
    pub updated_by: String,
}

pub fn get_by_addr(pool: &PoolType, node_addr: &str) -> Result<NodeResponse, ApiError> {
    use crate::schema::nodes::dsl::{addr, nodes};

    let not_found = format!("Node {} not found", node_addr);
    let conn = pool.get()?;
    let node = nodes
        .filter(addr.eq(node_addr.to_string()))
        .first::<Node>(&conn)
        .map_err(|_| ApiError::NotFound(not_found))?;

    let customer: Option<UserResponse> = if node.customer.is_some() {
        find(pool, &node.customer.as_ref().unwrap()).ok()
    } else {
        None
    };

    let sub: Option<UserResponse> = if node.sub.is_some() {
        find(pool, &node.sub.as_ref().unwrap()).ok()
    } else {
        None
    };

    Ok(NodeResponse {
        info: get_node_info(&node.addr).ok(),
        node,
        customer,
        sub,
    })
}

pub fn get_count(
    pool: &PoolType,
    _options: &QueryOptionRequest,
    auth_user: &AuthUser,
) -> Result<u32, ApiError> {
    use crate::schema::nodes::dsl::{customer, nodes, sub};

    let mut query = nodes.into_boxed();

    // check user role
    let role = Role::from_str(&auth_user.role).unwrap_or(Role::None);
    match role {
        Role::Admin => {
            // no customer or sub filter, can query all
        }
        Role::Cstm => {
            // customer filter
            query = query.filter(customer.eq(auth_user.id.to_string()));
        }
        Role::Sub => {
            // sub filter
            query = query.filter(sub.eq(auth_user.id.to_string()))
        }
        Role::None => return Err(ApiError::BadRequest("role fail".to_string())),
    }

    let conn = pool.get()?;
    let total: i64 = query.count().get_result(&conn).unwrap();

    Ok(total as u32)
}

pub fn get_by_user(
    pool: &PoolType,
    options: &QueryOptionRequest,
    auth_user: &AuthUser,
) -> Result<NodeResponses, ApiError> {
    use crate::schema::node_infos::dsl::node_infos;
    use crate::schema::nodes::dsl::{created_by, customer, nodes, server_id, server_idx, sub};

    //joinable!(nodes -> users (created_by));
    //allow_tables_to_appear_in_same_query!(users, nodes);

    let mut query = nodes.into_boxed();

    // check user role
    let role = Role::from_str(&auth_user.role).unwrap_or(Role::None);
    match role {
        Role::Admin => {
            // no customer or sub filter, can query all
        }
        Role::Cstm => {
            // customer filter
            query = query.filter(customer.eq(auth_user.id.to_string()));
        }
        Role::Sub => {
            // sub filter
            query = query.filter(sub.eq(auth_user.id.to_string()))
        }
        Role::None => return Err(ApiError::BadRequest("role fail".to_string())),
    }

    // check sort
    if options.order.is_some() {
        // list supported sort fields, this is ugly code!!!
        let order = options.order.as_ref().unwrap();
        match order.field.as_ref().map(String::as_str) {
            Some("server_id") => {
                if order.sort.unwrap_or(0) == 0 {
                    query = query.order_by(server_id.asc());
                } else {
                    query = query.order_by(server_id.desc());
                }
            }
            Some("customer") => {
                if order.sort.unwrap_or(0) == 0 {
                    query = query.order_by(customer.asc());
                } else {
                    query = query.order_by(customer.desc());
                }
            }
            Some("sub") => {
                if order.sort.unwrap_or(0) == 0 {
                    query = query.order_by(sub.asc());
                } else {
                    query = query.order_by(sub.desc());
                }
            }
            Some("server_idx") => {
                if order.sort.unwrap_or(0) == 0 {
                    query = query.order_by(server_idx.asc());
                } else {
                    query = query.order_by(server_idx.desc());
                }
            }
            _ => {}
        }
    } else {
        // use default
        query = query.order_by(created_by.desc());
    }

    let total = get_count(pool, options, auth_user)?;
    let conn = pool.get()?;
    //let total: i64 = query.count().get_result(&conn).unwrap();
    let mut result = NodeResponses {
        nodes: vec![],
        total,
        page_current: 0,
        page_size: DEFAULT_PAGE_SIZE as u32,
    };

    // check page
    if options.page.is_some() {
        let page = options.page.as_ref().unwrap();
        query = query
            .offset(((page.current - 1) * page.size) as i64)
            .limit(page.size as i64);
        result.page_size = page.size;
        result.page_current = page.current;
    } else {
        // user default, page size 20
        query = query.limit(DEFAULT_PAGE_SIZE);
    }
    //let filter_nodes = query.load::<Node>(&conn)?;
    //joinable!(node_infos -> nodes (node_infos.addr));
    let data = nodes.inner_join(node_infos).load(&conn)?;
    /*for node in filter_nodes {
        let node_customer: Option<UserResponse> = if node.customer.is_some() {
            find(pool, &node.customer.as_ref().unwrap()).ok()
        } else {
            None
        };
        let node_sub: Option<UserResponse> = if node.sub.is_some() {
            find(pool, &node.sub.as_ref().unwrap()).ok()
        } else {
            None
        };

        result.nodes.push(NodeResponse {
            info: get_node_info(&node.addr).ok(),
            node,
            customer: node_customer,
            sub: node_sub,
        })
    }*/

    Ok(result)
}
/*
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
*/

pub fn create_node(pool: &PoolType, new_node: &Node) -> Result<Node, ApiError> {
    use crate::schema::nodes::dsl::nodes;

    let conn = pool.get()?;
    diesel::insert_into(nodes).values(new_node).execute(&conn)?;
    Ok(new_node.clone().into())
}

pub fn update_node(pool: &PoolType, update_node: &UpdateNode) -> Result<NodeResponse, ApiError> {
    use crate::schema::nodes::dsl::{addr, nodes};

    let conn = pool.get()?;
    diesel::update(nodes)
        .filter(addr.eq(update_node.addr.clone()))
        .set(update_node)
        .execute(&conn)?;

    get_by_addr(&pool, &update_node.addr)
}

pub fn assign_nodes_for_customer(
    pool: &PoolType,
    params: &AssignCustomerNodesRequest,
    admin_user_id: &str,
) -> Result<(), ApiError> {
    use crate::schema::nodes::dsl::nodes;
    let cluster = load_by_server_cluster(&params.server_id)?;

    for update in &cluster.updates {
        let id: u32 = update.id.parse().unwrap();
        if id >= params.node_start && id <= params.node_end {
            println!("cluster:{:?}", update.id);
            // create or update node
            let node: Node = NewNode {
                addr: update.address.clone(),
                server_id: params.server_id.clone(),
                server_idx: id as i32,
                customer: Some(params.customer.clone()),
                sub: None,
                created_by: admin_user_id.to_string(),
                updated_by: admin_user_id.to_string(),
            }
            .into();

            let conn = pool.get()?;
            diesel::replace_into(nodes).values(&node).execute(&conn)?;
        }
    }

    Ok(())
}

pub fn assign_nodes_for_sub(
    pool: &PoolType,
    params: &AssignSubNodesRequest,
    cstm_user_id: &str,
) -> Result<(), ApiError> {
    use crate::schema::nodes::dsl::*;
    let conn = pool.get()?;

    let target = nodes
        .filter(addr.eq_any(params.addresses.clone()))
        .filter(customer.eq(cstm_user_id.to_string()));

    diesel::update(target)
        .set((
            sub.eq(params.sub.clone()),
            updated_at.eq(Utc::now().naive_utc()),
        ))
        .execute(&conn)?;

    Ok(())
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
    use crate::handlers::node::{QueryPage, QuerySort};
    use crate::models::node_json::update_node_status;
    use crate::models::user::tests::create_user;
    use crate::tests::helpers::tests::get_pool;
    use chrono::Utc;

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
    fn it_gets_by_addr() {
        let pool = get_pool();

        let node = create_new_test_node().unwrap();

        let find_result = get_by_addr(&pool, &node.addr).unwrap();
        assert_eq!(find_result.node.addr, node.addr);
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
        assert_eq!(result.node.sub, Some("newsub".to_string()));
    }

    #[test]
    fn it_assign_nodes() {
        // create admin
        let admin = create_user("admin".to_string()).unwrap();

        // create new customer
        let cstm = create_user("cstm".to_string()).unwrap();
        let params = AssignCustomerNodesRequest {
            customer: cstm.id.to_string(),
            server_id: "0001".to_string(),
            node_start: 110,
            node_end: 120,
        };
        assert!(assign_nodes_for_customer(&get_pool(), &params, &admin.id.to_string()).is_ok());

        // trigger update node status
        let _ = update_node_status();

        // query nodes for customer
        let nodes = get_by_user(
            &get_pool(),
            &QueryOptionRequest {
                page: None,
                order: None,
            },
            &cstm.clone().into(),
        )
        .unwrap();
        assert_eq!(nodes.nodes.len(), 11);

        // now assign some nodes to sub
        // create sub user
        let sub = create_user("sub".to_string()).unwrap();
        let assign_params = AssignSubNodesRequest {
            sub: sub.id.to_string(),
            addresses: vec![
                nodes.nodes[0].node.addr.clone(),
                nodes.nodes[2].node.addr.clone(),
            ],
        };
        let _ = assign_nodes_for_sub(&get_pool(), &assign_params, &cstm.id.to_string());

        // check if update success, query target node
        let node0 = get_by_addr(&get_pool(), &nodes.nodes[0].node.addr).unwrap();
        let node2 = get_by_addr(&get_pool(), &nodes.nodes[2].node.addr).unwrap();
        let node3 = get_by_addr(&get_pool(), &nodes.nodes[3].node.addr).unwrap();

        assert_eq!(node0.node.sub, Some(sub.id.to_string()));
        assert_eq!(node2.node.sub, Some(sub.id.to_string()));
        // others not change
        assert_eq!(node3.node.sub, None);
    }

    #[test]
    fn it_page_sort() {
        let admin = create_user("admin".to_string()).unwrap();

        // create new customer
        let cstm = create_user("cstm".to_string()).unwrap();
        let params = AssignCustomerNodesRequest {
            customer: cstm.id.to_string(),
            server_id: "0001".to_string(),
            node_start: 100,
            node_end: 175,
        };

        assert!(assign_nodes_for_customer(&get_pool(), &params, &admin.id.to_string()).is_ok());

        // trigger update node status
        let _ = update_node_status();

        let nodes = get_by_user(
            &get_pool(),
            &QueryOptionRequest {
                page: None,
                order: None,
            },
            &cstm.clone().into(),
        )
        .unwrap();
        assert_eq!(nodes.nodes.len(), DEFAULT_PAGE_SIZE as usize);

        let page = QueryPage {
            current: 1,
            size: 10,
        };
        let nodes = get_by_user(
            &get_pool(),
            &QueryOptionRequest {
                page: Some(page),
                order: None,
            },
            &cstm.clone().into(),
        )
        .unwrap();
        assert_eq!(nodes.nodes.len(), 10);

        // test count
        let total = get_count(
            &get_pool(),
            &QueryOptionRequest {
                page: None,
                order: None,
            },
            &cstm.clone().into(),
        )
        .unwrap();
        assert_eq!(total, 76);

        // test page correct
        let page = QueryPage {
            current: 4,
            size: 10,
        };
        let order = QuerySort {
            field: Some("server_idx".to_string()),
            sort: Some(0),
        };
        let nodes = get_by_user(
            &get_pool(),
            &QueryOptionRequest {
                page: Some(page.clone()),
                order: Some(order),
            },
            &cstm.clone().into(),
        )
        .unwrap();
        assert_eq!(nodes.nodes[0].node.server_idx, 130);

        let order = QuerySort {
            field: Some("server_idx".to_string()),
            sort: Some(1),
        };
        let nodes = get_by_user(
            &get_pool(),
            &QueryOptionRequest {
                page: Some(page),
                order: Some(order),
            },
            &cstm.clone().into(),
        )
        .unwrap();
        assert_eq!(nodes.nodes[0].node.server_idx, 145);

        let count = get_count(
            &get_pool(),
            &QueryOptionRequest {
                page: None,
                order: None,
            },
            &cstm.clone().into(),
        )
        .unwrap();

        assert_eq!(count, 76);
    }

    #[test]
    fn formal_assign_nodes() {
        // should not put into test!!!
        // dahao
        /*let params = AssignCustomerNodesRequest {
            customer: "e497059d-7c4e-4516-9a83-ee3dd629c0b7".to_string(),
            server_id: "0003".to_string(),
            node_start: 0,
            node_end: 99,
        };
        assert!(assign_nodes_for_customer(
            &get_pool(),
            &params,
            "6e031d1c-c313-47b6-9cc9-683a28ae9ab3",
        )
        .is_ok());

        let params = AssignCustomerNodesRequest {
            customer: "e497059d-7c4e-4516-9a83-ee3dd629c0b7".to_string(),
            server_id: "0004".to_string(),
            node_start: 0,
            node_end: 99,
        };
        assert!(assign_nodes_for_customer(
            &get_pool(),
            &params,
            "6e031d1c-c313-47b6-9cc9-683a28ae9ab3",
        )
        .is_ok());

        let params = AssignCustomerNodesRequest {
            customer: "e497059d-7c4e-4516-9a83-ee3dd629c0b7".to_string(),
            server_id: "0005".to_string(),
            node_start: 0,
            node_end: 99,
        };
        assert!(assign_nodes_for_customer(
            &get_pool(),
            &params,
            "6e031d1c-c313-47b6-9cc9-683a28ae9ab3",
        )
        .is_ok());

        let params = AssignCustomerNodesRequest {
            customer: "e497059d-7c4e-4516-9a83-ee3dd629c0b7".to_string(),
            server_id: "0006".to_string(),
            node_start: 0,
            node_end: 99,
        };
        assert!(assign_nodes_for_customer(
            &get_pool(),
            &params,
            "6e031d1c-c313-47b6-9cc9-683a28ae9ab3",
        )
        .is_ok());

        let params = AssignCustomerNodesRequest {
            customer: "e497059d-7c4e-4516-9a83-ee3dd629c0b7".to_string(),
            server_id: "0007".to_string(),
            node_start: 0,
            node_end: 99,
        };
        assert!(assign_nodes_for_customer(
            &get_pool(),
            &params,
            "6e031d1c-c313-47b6-9cc9-683a28ae9ab3",
        )
        .is_ok());

        let params = AssignCustomerNodesRequest {
            customer: "e497059d-7c4e-4516-9a83-ee3dd629c0b7".to_string(),
            server_id: "0008".to_string(),
            node_start: 0,
            node_end: 99,
        };
        assert!(assign_nodes_for_customer(
            &get_pool(),
            &params,
            "6e031d1c-c313-47b6-9cc9-683a28ae9ab3",
        )
        .is_ok());*/

        // longda
        /*let params = AssignCustomerNodesRequest {
            customer: "e150535f-c285-41b8-9e34-e7cac1c9d09c".to_string(),
            server_id: "0009".to_string(),
            node_start: 50,
            node_end: 69,
        };
        assert!(assign_nodes_for_customer(
            &get_pool(),
            &params,
            "6e031d1c-c313-47b6-9cc9-683a28ae9ab3",
        )
        .is_ok());*/

        // longda-gaosiming
        /*let assign_params = AssignSubNodesRequest {
            sub: "98d0e3c3-dfd8-403a-863c-bda8a93a7728".to_string(),
            addresses: vec!["0xeed21b0f4ddb012d11c8b9d9fa49bc78579864cb".to_string()],
        };
        assign_nodes_for_sub(
            &get_pool(),
            &assign_params,
            "e150535f-c285-41b8-9e34-e7cac1c9d09c",
        )
        .unwrap();*/

        // yuanjin
        /*let params = AssignCustomerNodesRequest {
            customer: "7fc16dc4-6adf-4cb5-b9dc-6dab5526dcd5".to_string(),
            server_id: "0009".to_string(),
            node_start: 0,
            node_end: 49,
        };
        assert!(assign_nodes_for_customer(
            &get_pool(),
            &params,
            "6e031d1c-c313-47b6-9cc9-683a28ae9ab3",
        )
        .is_ok());*/

        /*let params = AssignCustomerNodesRequest {
            customer: "7fc16dc4-6adf-4cb5-b9dc-6dab5526dcd5".to_string(),
            server_id: "0010".to_string(),
            node_start: 0,
            node_end: 99,
        };
        assert!(assign_nodes_for_customer(
            &get_pool(),
            &params,
            "6e031d1c-c313-47b6-9cc9-683a28ae9ab3",
        )
        .is_ok());*/

        /*let params = AssignCustomerNodesRequest {
            customer: "7fc16dc4-6adf-4cb5-b9dc-6dab5526dcd5".to_string(),
            server_id: "0012".to_string(),
            node_start: 0,
            node_end: 99,
        };
        assert!(assign_nodes_for_customer(
            &get_pool(),
            &params,
            "6e031d1c-c313-47b6-9cc9-683a28ae9ab3",
        )
        .is_ok());

        let params = AssignCustomerNodesRequest {
            customer: "7fc16dc4-6adf-4cb5-b9dc-6dab5526dcd5".to_string(),
            server_id: "0013".to_string(),
            node_start: 0,
            node_end: 99,
        };
        assert!(assign_nodes_for_customer(
            &get_pool(),
            &params,
            "6e031d1c-c313-47b6-9cc9-683a28ae9ab3",
        )
        .is_ok());*/
    }
}
