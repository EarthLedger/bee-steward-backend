use crate::database::PoolType;
use crate::errors::ApiError;
use crate::helpers::{respond_json, respond_ok};
use crate::models::user::{AuthUser, Role, User};
use crate::response::Response;
use actix_web::web::{block, Data, HttpResponse, Json, Path};

/*
pub async fn query_cluster(
    pool: Data<PoolType>,
    params: Json<QueryClusterRequest>,
    auth_user: AuthUser,
) -> Result<Json<Response<QueryClusterResponse>>, ApiError> {
}*/

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct NodeResponse {
    pub addr: String,
    pub server_id: String,
    pub server_idx: i32,
    pub customer: String,
    pub sub: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct NodesResponse(pub Vec<NodeResponse>);
