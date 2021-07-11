use crate::auth::{decode_jwt, PrivateClaim};
use crate::models::user::AuthUser;
use actix_identity::RequestIdentity;
use actix_web::{
    dev::Payload,
    web::{HttpRequest, HttpResponse},
    Error, FromRequest,
};
use futures::future::{err, ok, Ready};

/// Extractor for pulling the identity out of a request.
///
/// Simply add "user: AuthUser" to a handler to invoke this.
impl FromRequest for AuthUser {
    type Error = Error;
    type Config = ();
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let extract_token = || -> &str {
            match req.headers().get("token") {
                Some(value) => value.to_str().unwrap_or("".into()),
                None => "".into(),
            }
        };

        let identity = match RequestIdentity::get_identity(req) {
            Some(cookie_auth) => cookie_auth,
            None => extract_token().to_string(),
        };

        let private_claim = decode_jwt(&identity);

        if private_claim.is_ok() {
            let private_claim = private_claim.unwrap();
            return ok(AuthUser {
                id: private_claim.user_id.to_string(),
                username: private_claim.username,
                role: private_claim.role,
            });
        } else {
            err(HttpResponse::Unauthorized().into())
        }

        /*let identity = RequestIdentity::get_identity(req);
        if let Some(identity) = identity {
            let private_claim: PrivateClaim = decode_jwt(&identity).unwrap();
            return ok(AuthUser {
                id: private_claim.user_id.to_string(),
                username: private_claim.username,
                role: private_claim.role,
            });
        }
        err(HttpResponse::Unauthorized().into())*/
    }
}
