#[cfg(test)]
mod tests {
    use crate::handlers::user::CreateUserRequest;
    use crate::tests::helpers::tests::{assert_get, assert_post};
    use uuid::Uuid;

    const PATH: &str = "/api/v1/user";

    #[actix_rt::test]
    async fn it_gets_all_users() {
        assert_get(PATH).await;
    }

    #[actix_rt::test]
    async fn it_creates_a_user() {
        let params = CreateUserRequest {
            username: Uuid::new_v4().to_string(),
            password: "123456".into(),
            role: "admin".into(),
        };
        assert_post(PATH, params).await;
    }
}
