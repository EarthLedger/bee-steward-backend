use crate::auth::{create_jwt, hash, PrivateClaim};
use crate::database::PoolType;
use crate::errors::ApiError;
use crate::handlers::user::UserResponse;
use crate::helpers::respond_json;
use crate::models::user::find_by_auth;
use crate::response::Response;
use crate::validate::validate;
use actix_identity::Identity;
use actix_web::web::{block, Data, Json};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, Validate)]
pub struct LoginRequest {
    #[validate(length(
        min = 3,
        message = "username is required and must be at least 3 characters"
    ))]
    pub username: String,

    #[validate(length(
        min = 6,
        message = "password is required and must be at least 6 characters"
    ))]
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct LoginResponse {
    pub id: Uuid,
    pub username: String,
    pub token: String,
}

impl From<UserResponse> for LoginResponse {
    fn from(user: UserResponse) -> Self {
        LoginResponse {
            id: user.id,
            username: user.username.to_string(),
            token: "".to_string(),
        }
    }
}

/// Login a user
/// Create and remember their JWT
pub async fn login(
    id: Identity,
    pool: Data<PoolType>,
    params: Json<LoginRequest>,
) -> Result<Json<Response<LoginResponse>>, ApiError> {
    validate(&params)?;

    // Validate that the email + hashed password matches
    let hashed = hash(&params.password);
    let user = block(move || find_by_auth(&pool, &params.username, &hashed)).await?;

    // Create a JWT
    let private_claim = PrivateClaim::new(user.id, user.username.clone(), user.role.clone());
    let jwt = create_jwt(private_claim)?;

    // Remember the token
    let mut login_response: LoginResponse = user.into();
    login_response.token = jwt.clone();
    id.remember(jwt);
    respond_json(Response {
        code: 200,
        msg: "success".to_string(),
        data: login_response,
    })
}

/// Logout a user
/// Forget their user_id
pub async fn logout(id: Identity) -> Result<Json<Response<String>>, ApiError> {
    id.forget();
    respond_json(Response {
        code: 200,
        msg: "success".to_string(),
        data: "ok".to_string(),
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tests::helpers::tests::get_data_pool;
    use actix_identity::Identity;
    use actix_web::{test, FromRequest};

    async fn get_identity() -> Identity {
        let (request, mut payload) =
            test::TestRequest::with_header("content-type", "application/json").to_http_parts();
        let identity = Option::<Identity>::from_request(&request, &mut payload)
            .await
            .unwrap()
            .unwrap();
        identity
    }

    async fn login_user() -> Result<Json<Response<LoginResponse>>, ApiError> {
        let params = LoginRequest {
            username: "satoshi@nakamotoinstitute.org".into(),
            password: "123456".into(),
        };
        let identity = get_identity().await;
        login(identity, get_data_pool(), Json(params)).await
    }

    async fn logout_user() -> Result<Json<Response<String>>, ApiError> {
        let identity = get_identity().await;
        logout(identity).await
    }

    #[actix_rt::test]
    async fn it_logs_a_user_in() {
        let response = login_user().await;
        assert!(response.is_ok());
    }

    #[actix_rt::test]
    async fn it_logs_a_user_out() {
        login_user().await.unwrap();
        let response = logout_user().await;
        assert!(response.is_ok());
    }
}
