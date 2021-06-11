use crate::auth::hash;
use crate::database::PoolType;
use crate::errors::ApiError;
use crate::handlers::user::{UserResponse, UsersResponse};
use crate::schema::users;
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use std::str::FromStr;
use strum_macros::{Display, EnumString};
use uuid::Uuid;

#[derive(Debug, PartialEq, EnumString, Display)]
pub enum Role {
    #[strum(serialize = "admin")]
    Admin,

    #[strum(serialize = "cstm")]
    Cstm,

    #[strum(serialize = "sub")]
    Sub,

    #[strum(serialize = "none")]
    None,
}

impl Role {
    pub fn is_op_permit(&self, op_target: &Role) -> bool {
        match op_target {
            Role::Admin => {
                // only admin can operate admin
                *self == Role::Admin
            }
            Role::Cstm => {
                // only admin can operation cstm
                *self == Role::Admin
            }
            Role::Sub => {
                // admin and cstm cann operate sub
                *self == Role::Admin || *self == Role::Cstm
            }
            Role::None => false,
        }
    }

    pub fn is_admin(role: &str) -> bool {
        Role::from_str(role).unwrap_or(Role::None) == Role::Admin
    }

    pub fn is_valid(role: &str) -> bool {
        role == Role::Admin.to_string()
            || role == Role::Cstm.to_string()
            || role == Role::Sub.to_string()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Queryable, Identifiable, Insertable)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password: String,
    pub role: String,
    pub created_by: String,
    pub created_at: NaiveDateTime,
    pub updated_by: String,
    pub updated_at: NaiveDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewUser {
    pub id: String,
    pub username: String,
    pub password: String,
    pub role: String,
    pub created_by: String,
    pub updated_by: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, AsChangeset)]
#[table_name = "users"]
pub struct UpdateUser {
    pub id: String,
    pub username: String,
    pub role: String,
    pub updated_by: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: String,
    pub username: String,
    pub role: String,
}

/// Get all users
pub fn get_all(pool: &PoolType) -> Result<UsersResponse, ApiError> {
    use crate::schema::users::dsl::users;

    let conn = pool.get()?;
    let all_users = users.load(&conn)?;

    Ok(all_users.into())
}

/// Find a user by the user's id or error out
pub fn find(pool: &PoolType, user_id: &Uuid) -> Result<UserResponse, ApiError> {
    use crate::schema::users::dsl::{id, users};

    let not_found = format!("User {} not found", user_id);
    let conn = pool.get()?;
    let user = users
        .filter(id.eq(user_id.to_string()))
        .first::<User>(&conn)
        .map_err(|_| ApiError::NotFound(not_found))?;

    Ok(user.into())
}

/// Find a user by the user's authentication information (email + password)
/// Return an Unauthorized error if it doesn't match
pub fn find_by_auth(
    pool: &PoolType,
    user_username: &str,
    user_password: &str,
) -> Result<UserResponse, ApiError> {
    use crate::schema::users::dsl::{password, username, users};

    let conn = pool.get()?;
    let user = users
        .filter(username.eq(user_username.to_string()))
        .filter(password.eq(user_password.to_string()))
        .first::<User>(&conn)
        .map_err(|e| {
            println!("?{}", e);
            ApiError::Unauthorized("Invalid login".into())
        })?;
    Ok(user.into())
}

/// Create a new user
pub fn create(pool: &PoolType, new_user: &User) -> Result<UserResponse, ApiError> {
    use crate::schema::users::dsl::users;

    let conn = pool.get()?;
    diesel::insert_into(users).values(new_user).execute(&conn)?;
    Ok(new_user.clone().into())
}

/// Update a user
pub fn update(pool: &PoolType, update_user: &UpdateUser) -> Result<UserResponse, ApiError> {
    use crate::schema::users::dsl::{id, users};

    let conn = pool.get()?;
    diesel::update(users)
        .filter(id.eq(update_user.id.clone()))
        .set(update_user)
        .execute(&conn)?;
    find(&pool, &Uuid::parse_str(&update_user.id)?)
}

/// Delete a user
pub fn delete(pool: &PoolType, user_id: Uuid) -> Result<(), ApiError> {
    use crate::schema::users::dsl::{id, users};

    let conn = pool.get()?;
    diesel::delete(users)
        .filter(id.eq(user_id.to_string()))
        .execute(&conn)?;
    Ok(())
}

impl From<NewUser> for User {
    fn from(user: NewUser) -> Self {
        User {
            id: user.id,
            username: user.username,
            password: hash(&user.password),
            role: user.role,
            created_by: user.created_by,
            created_at: Utc::now().naive_utc(),
            updated_by: user.updated_by,
            updated_at: Utc::now().naive_utc(),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tests::helpers::tests::get_pool;

    pub fn get_all_users() -> Result<UsersResponse, ApiError> {
        let pool = get_pool();
        get_all(&pool)
    }

    pub fn create_user() -> Result<UserResponse, ApiError> {
        let user_id = Uuid::new_v4();
        let new_user = NewUser {
            id: user_id.to_string(),
            username: user_id.to_string(),
            password: "123456".to_string(),
            role: "admin".to_string(),
            created_by: user_id.to_string(),
            updated_by: user_id.to_string(),
        };
        let user: User = new_user.into();
        create(&get_pool(), &user)
    }

    #[test]
    fn it_gets_a_user() {
        let users = get_all_users();
        assert!(users.is_ok());
    }

    #[test]
    fn test_find() {
        let users = get_all_users().unwrap();
        let user = &users.0[0];
        let found_user = find(&get_pool(), &user.id).unwrap();
        assert_eq!(user, &found_user);
    }

    #[test]
    fn it_doesnt_find_a_user() {
        let user_id = Uuid::new_v4();
        let not_found_user = find(&get_pool(), &user_id);
        assert!(not_found_user.is_err());
    }

    #[test]
    fn it_creates_a_user() {
        let created = create_user();
        assert!(created.is_ok());
        let unwrapped = created.unwrap();
        let found_user = find(&get_pool(), &unwrapped.id).unwrap();
        assert_eq!(unwrapped, found_user);
    }

    #[test]
    fn it_updates_a_user() {
        let users = get_all_users().unwrap();
        let user = &users.0[1];
        let update_user = UpdateUser {
            id: user.id.to_string(),
            username: Uuid::new_v4().to_string(),
            role: "admin".to_string(),
            updated_by: user.id.to_string(),
        };
        let updated = update(&get_pool(), &update_user);
        assert!(updated.is_ok());
        let found_user = find(&get_pool(), &user.id).unwrap();
        assert_eq!(updated.unwrap(), found_user);
    }

    #[test]
    fn it_fails_to_update_a_nonexistent_user() {
        let user_id = Uuid::new_v4();
        let update_user = UpdateUser {
            id: user_id.to_string(),
            username: "ModelUpdateFailure".to_string(),
            role: "admin".to_string(),
            updated_by: user_id.to_string(),
        };
        let updated = update(&get_pool(), &update_user);
        assert!(updated.is_err());
    }

    #[test]
    fn it_deletes_a_user() {
        let created = create_user();
        let user_id = created.unwrap().id;
        let user = find(&get_pool(), &user_id);
        assert!(user.is_ok());
        delete(&get_pool(), user_id).unwrap();
        let user = find(&get_pool(), &user_id);
        assert!(user.is_err());
    }

    #[test]
    fn role_string_conversion() {
        let admin = Role::Admin;
        assert_eq!(String::from("admin"), admin.to_string());

        let cstm = Role::from_str("cstm").unwrap();
        assert_eq!(Role::Cstm, cstm);
    }
}
