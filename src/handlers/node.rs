use crate::database::PoolType;
use crate::errors::ApiError;
use crate::helpers::{respond_json, respond_ok};
use crate::models::node::{
    assign_nodes_for_customer, assign_nodes_for_sub, get_by_customer, get_by_sub, Node,
};
use crate::models::node_json::NodeInfo;
use crate::models::user::{AuthUser, Role, User};
use crate::response::{Response, SUCCESS};
use actix_web::web::{block, Data, HttpResponse, Json, Path};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QueryCustomerNodeRequest {
    pub customer: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuerySubNodeRequest {
    pub sub: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct NodeResponse {
    pub node: Node,
    pub info: NodeInfo,
}

pub type NodeResponses = Vec<NodeResponse>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AssignCustomerNodesRequest {
    pub customer: String,
    pub server_id: String,
    pub node_start: u32,
    pub node_end: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AssignSubNodesRequest {
    pub sub: String,
    pub addresses: Vec<String>,
}

/// query by customer
pub async fn query_by_customer(
    pool: Data<PoolType>,
    params: Json<QueryCustomerNodeRequest>,
    auth_user: AuthUser,
) -> Result<Json<Response<NodeResponses>>, ApiError> {
    // Admin could query any nodes
    // Customer user can only query nodes which belongs to
    let customer_id = if !Role::is_admin(&auth_user.role) {
        &auth_user.id
    } else {
        &params.customer
    };

    let nodes = get_by_customer(&pool, customer_id)?;

    respond_json(Response {
        code: 200,
        msg: SUCCESS.to_string(),
        data: nodes,
    })
}

/// query by sub
pub async fn query_by_sub(
    pool: Data<PoolType>,
    params: Json<QuerySubNodeRequest>,
    auth_user: AuthUser,
) -> Result<Json<Response<NodeResponses>>, ApiError> {
    // Admin could query any nodes
    // Customer user can only query nodes which belongs to
    let sub_id = if !Role::is_admin(&auth_user.role) {
        // not admin, it could be customer or sub, only can query by user id
        &auth_user.id
    } else {
        // admin, trust query params
        &params.sub
    };

    let nodes = get_by_sub(&pool, sub_id)?;

    respond_json(Response {
        code: 200,
        msg: SUCCESS.to_string(),
        data: nodes,
    })
}

// assign nodes to customer
pub async fn assign_customer_nodes(
    pool: Data<PoolType>,
    params: Json<AssignCustomerNodesRequest>,
    auth_user: AuthUser,
) -> Result<Json<Response<()>>, ApiError> {
    // only admin can assign customer nodes
    if !Role::is_admin(&auth_user.role) {
        return Err(ApiError::ValidationError(vec![
            "role not permit".to_string()
        ]));
    } else {
        let _ = assign_nodes_for_customer(&pool, &params, &auth_user.id)?;
        respond_json(Response {
            code: 200,
            msg: SUCCESS.to_string(),
            data: (),
        })
    }
}

pub async fn assign_sub_nodes(
    pool: Data<PoolType>,
    params: Json<AssignSubNodesRequest>,
    auth_user: AuthUser,
) -> Result<Json<Response<()>>, ApiError> {
    // only admin can assign customer nodes
    if !Role::is_cstm(&auth_user.role) {
        return Err(ApiError::ValidationError(vec![
            "role not permit".to_string()
        ]));
    } else {
        let _ = assign_nodes_for_sub(&pool, &params, &auth_user.id)?;
        respond_json(Response {
            code: 200,
            msg: SUCCESS.to_string(),
            data: (),
        })
    }
}
