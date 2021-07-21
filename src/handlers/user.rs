use crate::auth::hash;
use crate::database::PoolType;
use crate::errors::ApiError;
use crate::handlers::node::QueryOptionRequest;
use crate::helpers::{respond_json, respond_ok};
use crate::models::user::{
    create, delete, find, get_users as model_get_users, update, AuthUser, NewUser, Role,
    UpdateUser, User,
};
use crate::response::{Response, SUCCESS};
use crate::validate::validate;
use actix_web::web::{block, Data, HttpResponse, Json, Path};
use serde::Serialize;
use std::str::FromStr;
use uuid::Uuid;
use validator::ValidationError;

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub created_by: Uuid,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct UsersResponse {
    pub users: Vec<UserResponse>,
    pub total: u32,
    pub page_current: u32,
    pub page_size: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, Validate)]
pub struct CreateUserRequest {
    #[validate(length(
        min = 3,
        message = "name is required and must be at least 3 characters"
    ))]
    pub username: String,

    #[validate(length(
        min = 6,
        message = "password is required and must be at least 6 characters"
    ))]
    pub password: String,

    #[validate(length(min = 1), custom = "validate_user_role")]
    pub role: String,
}

fn validate_user_role(role: &str) -> Result<(), ValidationError> {
    if !Role::is_valid(role) {
        return Err(ValidationError::new("not valid user role"));
    }

    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, Validate)]
pub struct UpdateUserRequest {
    #[validate(length(
        min = 3,
        message = "name is required and must be at least 3 characters"
    ))]
    pub username: String,
    #[validate(length(
        min = 6,
        message = "password is required and must be at least 6 characters"
    ))]
    pub password: String,

    pub role: String,
}

/// Get a user
pub async fn get_user(
    user_id: Path<Uuid>,
    pool: Data<PoolType>,
) -> Result<Json<UserResponse>, ApiError> {
    let user = block(move || find(&pool, &user_id.to_string())).await?;
    respond_json(user)
}

/// Get login user info
pub async fn get_login_user_info(
    auth_user: AuthUser,
    pool: Data<PoolType>,
) -> Result<Json<Response<UserResponse>>, ApiError> {
    let user = block(move || find(&pool, &auth_user.id.to_string())).await?;
    respond_json(Response {
        code: 200,
        msg: "success".to_string(),
        data: user,
    })
}

/// Get all users
pub async fn get_users(
    pool: Data<PoolType>,
    params: Json<QueryOptionRequest>,
    auth_user: AuthUser,
) -> Result<Json<Response<UsersResponse>>, ApiError> {
    let users = block(move || model_get_users(&pool, &auth_user, &params)).await?;
    respond_json(Response {
        code: 200,
        msg: SUCCESS.to_string(),
        data: users,
    })
}

/// Create a user
pub async fn create_user(
    pool: Data<PoolType>,
    params: Json<CreateUserRequest>,
    auth_user: AuthUser,
) -> Result<Json<Response<UserResponse>>, ApiError> {
    validate(&params)?;

    info!("login user: {:?}", auth_user);
    // user role verification
    let new_user_role = Role::from_str(&params.role).unwrap();
    if !Role::from_str(&auth_user.role)
        .unwrap()
        .is_op_permit(&new_user_role)
    {
        warn!("operation not permitted for role: {:?}", new_user_role);
        return Err(ApiError::ValidationError(vec![
            "role not permit".to_string()
        ]));
    }

    // update when auth is added
    let user_id = Uuid::new_v4();
    let new_user: User = NewUser {
        id: user_id.to_string(),
        username: params.username.to_string(),
        password: params.password.to_string(),
        role: params.role.to_string(),
        created_by: auth_user.id.to_string(),
        updated_by: auth_user.id.to_string(),
    }
    .into();
    let user = block(move || create(&pool, &new_user)).await?;
    respond_json(Response {
        code: 200,
        msg: "success".to_string(),
        data: user,
    })
}

/// Update a user
pub async fn update_user(
    user_id: Path<Uuid>,
    pool: Data<PoolType>,
    params: Json<UpdateUserRequest>,
    auth_user: AuthUser,
) -> Result<Json<Response<UserResponse>>, ApiError> {
    validate(&params)?;

    // admin user can operate all
    if !Role::is_admin(&auth_user.role) {
        // not admin, only creator can operate
        // load update user
        let user = find(&pool, &user_id.to_string())?;
        if user.created_by != Uuid::parse_str(&auth_user.id).unwrap() {
            warn!(
                "update user, but not admin and not creator: {:?}",
                auth_user.id
            );
            return Err(ApiError::ValidationError(vec![
                "role not permit".to_string()
            ]));
        }

        // check role
        if !Role::is_sub(&params.role) {
            return Err(ApiError::ValidationError(vec![
                "role not permit".to_string()
            ]));
        }
    }

    // temporarily use the user's id for updated_at
    // update when auth is added
    let update_user = UpdateUser {
        id: user_id.to_string(),
        username: params.username.to_string(),
        password: hash(&params.password),
        role: params.role.to_string(),
        updated_by: user_id.to_string(),
    };
    let user = block(move || update(&pool, &update_user)).await?;
    respond_json(Response {
        code: 200,
        msg: "success".to_string(),
        data: user,
    })
}

/// Delete a user
pub async fn delete_user(
    user_id: Path<Uuid>,
    pool: Data<PoolType>,
) -> Result<HttpResponse, ApiError> {
    block(move || delete(&pool, *user_id)).await?;
    respond_ok()
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        UserResponse {
            id: Uuid::parse_str(&user.id).unwrap(),
            username: user.username.to_string(),
            role: user.role.to_string(),
            created_by: Uuid::parse_str(&user.created_by).unwrap(),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::models::user::tests::create_user as model_create_user;
    use crate::tests::helpers::tests::{get_data_pool, get_pool};
    use chrono::Utc;

    #[actix_rt::test]
    async fn it_doesnt_find_a_user() {
        let uuid = Uuid::new_v4();
        let user_id: Path<Uuid> = uuid.into();
        let response = get_user(user_id, get_data_pool()).await;
        let expected_error = ApiError::NotFound(format!("User {} not found", uuid.to_string()));
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), expected_error);
    }

    #[actix_rt::test]
    async fn it_creates_a_user() {
        let now = Utc::now();
        let params = Json(CreateUserRequest {
            username: format!("{}", now).into(),
            password: "123456".into(),
            role: "admin".into(),
        });
        let response = create_user(
            get_data_pool(),
            Json(params.clone()),
            AuthUser {
                id: "0000".to_string(),
                username: "test".to_string(),
                role: "admin".to_string(),
            },
        )
        .await
        .unwrap();
        assert_eq!(response.into_inner().data.username, params.username);
    }

    #[actix_rt::test]
    async fn it_deletes_a_user() {
        let created = model_create_user("admin".to_string());
        let user_id = created.unwrap().id;
        let user_id_path: Path<Uuid> = user_id.into();
        let user = find(&get_pool(), &user_id.to_string());
        assert!(user.is_ok());
        delete_user(user_id_path, get_data_pool()).await.unwrap();
        let user = find(&get_pool(), &user_id.to_string());
        assert!(user.is_err());
    }
}
