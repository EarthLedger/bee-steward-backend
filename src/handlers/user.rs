use crate::database::PoolType;
use crate::errors::ApiError;
use crate::helpers::{respond_json, respond_ok};
use crate::models::user::{
    create, delete, find, get_all, update, AuthUser, NewUser, UpdateUser, User,
};
use crate::response::Response;
use crate::validate::validate;
use actix_web::web::{block, Data, HttpResponse, Json, Path};
use rayon::prelude::*;
use serde::Serialize;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct UsersResponse(pub Vec<UserResponse>);

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
    pub role: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Validate)]
pub struct UpdateUserRequest {
    #[validate(length(
        min = 3,
        message = "name is required and must be at least 3 characters"
    ))]
    pub username: String,
    pub role: String,
}

/// Get a user
pub async fn get_user(
    user_id: Path<Uuid>,
    pool: Data<PoolType>,
) -> Result<Json<UserResponse>, ApiError> {
    let user = block(move || find(&pool, *user_id)).await?;
    respond_json(user)
}

/// Get login user info
pub async fn get_login_user_info(
    auth_user: AuthUser,
    pool: Data<PoolType>,
) -> Result<Json<Response<UserResponse>>, ApiError> {
    let user = block(move || find(&pool, Uuid::parse_str(&auth_user.id).unwrap())).await?;
    respond_json(Response {
        code: 200,
        msg: "success".to_string(),
        data: user,
    })
}

/// Get all users
pub async fn get_users(pool: Data<PoolType>) -> Result<Json<UsersResponse>, ApiError> {
    let users = block(move || get_all(&pool)).await?;
    respond_json(users)
}

/// Create a user
pub async fn create_user(
    pool: Data<PoolType>,
    params: Json<CreateUserRequest>,
    user: AuthUser,
) -> Result<Json<UserResponse>, ApiError> {
    validate(&params)?;

    info!("login user: {:?}", user);

    // temporarily use the new user's id for created_at/updated_at
    // update when auth is added
    let user_id = Uuid::new_v4();
    let new_user: User = NewUser {
        id: user_id.to_string(),
        username: params.username.to_string(),
        password: params.password.to_string(),
        role: params.role.to_string(),
        created_by: user_id.to_string(),
        updated_by: user_id.to_string(),
    }
    .into();
    let user = block(move || create(&pool, &new_user)).await?;
    respond_json(user.into())
}

/// Update a user
pub async fn update_user(
    user_id: Path<Uuid>,
    pool: Data<PoolType>,
    params: Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    validate(&params)?;

    // temporarily use the user's id for updated_at
    // update when auth is added
    let update_user = UpdateUser {
        id: user_id.to_string(),
        username: params.username.to_string(),
        role: params.role.to_string(),
        updated_by: user_id.to_string(),
    };
    let user = block(move || update(&pool, &update_user)).await?;
    respond_json(user.into())
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
        }
    }
}

impl From<Vec<User>> for UsersResponse {
    fn from(users: Vec<User>) -> Self {
        UsersResponse(users.into_par_iter().map(|user| user.into()).collect())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::models::user::tests::create_user as model_create_user;
    use crate::tests::helpers::tests::{get_data_pool, get_pool};

    pub fn get_all_users() -> UsersResponse {
        let pool = get_pool();
        get_all(&pool).unwrap()
    }

    pub fn get_first_users_id() -> Uuid {
        get_all_users().0[0].id
    }

    #[actix_rt::test]
    async fn it_gets_a_user() {
        let first_user = &get_all_users().0[0];
        let user_id: Path<Uuid> = get_first_users_id().into();
        let response = get_user(user_id, get_data_pool()).await.unwrap();
        assert_eq!(response.into_inner(), *first_user);
    }

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
    async fn it_gets_all_users() {
        let response = get_users(get_data_pool()).await;
        assert!(response.is_ok());
        assert_eq!(response.unwrap().into_inner().0[0], get_all_users().0[0]);
    }

    #[actix_rt::test]
    async fn it_creates_a_user() {
        let params = Json(CreateUserRequest {
            username: "satoshi@nakamotoinstitute.org".into(),
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
        assert_eq!(response.into_inner().username, params.username);
    }

    #[actix_rt::test]
    async fn it_updates_a_user() {
        let first_user = &get_all_users().0[0];
        let user_id: Path<Uuid> = get_first_users_id().into();
        let params = Json(UpdateUserRequest {
            username: first_user.username.clone(),
            role: first_user.role.clone(),
        });
        let response = update_user(user_id, get_data_pool(), Json(params.clone()))
            .await
            .unwrap();
        assert_eq!(response.into_inner().username, params.username);
    }

    #[actix_rt::test]
    async fn it_deletes_a_user() {
        let created = model_create_user();
        let user_id = created.unwrap().id;
        let user_id_path: Path<Uuid> = user_id.into();
        let user = find(&get_pool(), user_id);
        assert!(user.is_ok());
        delete_user(user_id_path, get_data_pool()).await.unwrap();
        let user = find(&get_pool(), user_id);
        assert!(user.is_err());
    }
}
