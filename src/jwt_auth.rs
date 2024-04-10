use chrono::{Duration, Utc};
use cookie::Cookie;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::convert::Infallible;
use uuid::Uuid;
use warp::{
    cookie::cookies, http::header::SET_COOKIE, reject, reply, Filter, Rejection, Reply,
};

use crate::config::Config;
use crate::model::{TokenClaims, User};
use crate::response::ErrorResponse;

#[derive(Debug)]
struct ExtractTokenError {
    message: String,
}

impl std::error::Error for ExtractTokenError {}

impl std::fmt::Display for ExtractTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

pub fn jwt_middleware(
    config: Config,
    pool: Pool<Postgres>,
) -> impl Filter<Extract = (Uuid, Option<TokenData<TokenClaims>>), Error = Rejection> + Clone {
    cookies()
        .and(with_config(config))
        .and(with_pool(pool))
        .and_then(|cookies: Vec<Cookie>, config: Config, pool: Pool<Postgres>| async move {
            let token = match extract_token_from_cookies(&cookies) {
                Ok(token) => token,
                Err(err) => {
                    return Err(warp::reject::custom(ErrorResponse {
                        status: "fail".to_string(),
                        message: err.to_string(),
                    }));
                }
            };

            let token_data = match decode::<TokenClaims>(
                &token,
                &DecodingKey::from_secret(config.jwt_secret.as_ref()),
                &Validation::default(),
            ) {
                Ok(token_data) => token_data,
                Err(_) => {
                    return Err(warp::reject::custom(ErrorResponse {
                        status: "fail".to_string(),
                        message: "Invalid token".to_string(),
                    }));
                }
            };

            let user_id = Uuid::parse_str(token_data.claims.sub.as_str()).unwrap();

            // Check if the token is still valid in the database
            let is_valid = sqlx::query_as!(
                User,
                "SELECT * FROM users WHERE id = $1 AND token = $2",
                user_id.to_string(),
                token
            )
            .fetch_optional(&pool)
            .await
            .map_or(false, |_| true);

            if !is_valid {
                return Err(warp::reject::custom(ErrorResponse {
                    status: "fail".to_string(),
                    message: "Invalid token".to_string(),
                }));
            }

            Ok((user_id, Some(token_data)))
        })
}

fn extract_token_from_cookies(cookies: &[Cookie]) -> Result<String, ExtractTokenError> {
    for cookie in cookies {
        if cookie.name() == "token" {
            return Ok(cookie.value().to_string());
        }
    }
    Err(ExtractTokenError {
        message: "Token not found in cookies".to_string(),
    })
}

fn with_config(
    config: Config,
) -> impl Filter<Extract = (Config,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || config.clone())
}

fn with_pool(
    pool: Pool<Postgres>,
) -> impl Filter<Extract = (Pool<Postgres>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || pool.clone())
}