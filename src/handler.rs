// use crate::{
//     config::Config,
//     jwt_auth,
//     model::{LoginUserSchema, RegisterUserSchema, TokenClaims, User},
//     response::FilteredUser,
// };
// // use cookie::Cookie;
// // use time::Duration as Dur;


// use argon2::{
//     password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
//     Argon2,
// };
// use chrono::{Duration, Utc};
// use jsonwebtoken::{encode, jwk, EncodingKey, Header};
// use serde_json::json;
// use sqlx::{Pool, Postgres, Row};
// use uuid::Uuid;
// use warp::{
//      Filter, Rejection, Reply, reply,
// };
// use warp::http::header::{HeaderValue, SET_COOKIE, CONTENT_TYPE};
// //use warp::{reply, http::header::SET_COOKIE, HeaderValue};

// fn filter_user_record(user: &User) -> FilteredUser {
//     FilteredUser {
//         id: user.id.to_string(),
//         email: user.email.to_string(),
//         name: user.name.to_string(),
//         photo: user.photo.to_string(),
//         role: user.role.to_string(),
//         verified: user.verified,
//         createdAt: user.created_at.unwrap(),
//         updatedAt: user.updated_at.unwrap(),
//     }
// }


// async fn register_user_handler(
//     body: RegisterUserSchema,
//     pool: Pool<Postgres>,
// ) -> Result<impl Reply, Rejection> {
//     let exists: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
//         .bind(body.email.to_owned())
//         .fetch_one(&pool)
//         .await
//         .unwrap()
//         .get(0);

//     if exists {
//         return Ok(warp::reply::json(&json!({
//             "status": "fail",
//             "message": "User with that email already exists"
//         })));
//     }

//     let salt = SaltString::generate(&mut OsRng);
//     let hashed_password = Argon2::default()
//         .hash_password(body.password.as_bytes(), &salt)
//         .expect("error while hashing password")
//         .to_string();

//     let query_result = sqlx::query_as!(
//         User,
//         "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
//         body.name.to_string(),
//         body.email.to_string().to_lowercase(),
//         hashed_password
//     )
//     .fetch_one(&pool)
//     .await;

//     match query_result {
//         Ok(user) => Ok(warp::reply::json(&json!({
//             "status": "success",
//             "data": json!({
//                 "user": filter_user_record(&user)
//             })
//         }))),
//         Err(e) => Ok(warp::reply::json(&json!({
//             "status": "error",
//             "message": format!("{:?}", e)
//         }))),
//     }
// }

// async fn login_user_handler(
//     body: LoginUserSchema,
//     config: Config,
//     pool: Pool<Postgres>,
// ) -> Result<warp::reply::WithHeader<warp::reply::Json>, Rejection> {
//     let query_result = sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", body.email)
//         .fetch_optional(&pool)
//         .await
//         .unwrap();

//     let is_valid = query_result.to_owned().map_or(false, |user| {
//         let parsed_hash = PasswordHash::new(&user.password).unwrap();
//         Argon2::default()
//             .verify_password(body.password.as_bytes(), &parsed_hash)
//             .map_or(false, |_| true)
//     });

//     if !is_valid {
//         let json_response = reply::json(&json!({
//             "status": "fail",
//             "message": "Invalid email or password."
//         }));

//         let response_with_fail = warp::reply::with_header(
//             json_response,
//             CONTENT_TYPE,
//             HeaderValue::from_static("application/json"),
//         );

//         return Ok(response_with_fail);
//     }

//     let user = query_result.unwrap();

//     let now = Utc::now();
//     let iat = now.timestamp() as usize;
//     let exp = (now + Duration::minutes(60)).timestamp() as usize;
//     let claims: TokenClaims = TokenClaims {
//         sub: user.id.to_string(),
//         exp,
//         iat,
//     };

//     let token = encode(
//         &Header::default(),
//         &claims,
//         &EncodingKey::from_secret(config.jwt_secret.as_ref()),
//     )
//     .unwrap();

//     let cookie_value = format!("token={}; Path=/; Max-Age={}; HttpOnly", token, 3600);

//     let json_response = reply::json(&json!({
//         "status": "success"
//     }));

//     let response_with_cookie = warp::reply::with_header(
//         json_response,
//         SET_COOKIE,
//         HeaderValue::from_str(&cookie_value).unwrap(),
//     );
//     return Ok(response_with_cookie);
// }

// // async fn logout_handler() -> Result<warp::reply::WithHeader<warp::reply::WithHeader<warp::reply::Json>>, Rejection> {
// //     // let cookie_value = "token=; Path=/; Max-Age=0; HttpOnly";
// //     let cookie = Cookie::build(("token", " "))
// //     .path("/")
// //     .max_age(Dur::new(-1, 0))  // Use http::header
// //     .http_only(true)
// //     .finish();

// //     let json_response = warp::reply::json(&json!({
// //         "status": "success"
// //     }));

// //     let response_with_cookie = warp::reply::with_header(
// //         json_response,
// //         SET_COOKIE,
// //         HeaderValue::from_str(&cookie.to_string()).unwrap(),
// //     );

// //     let response_with_json_content_type = warp::reply::with_header(
// //         response_with_cookie,
// //         CONTENT_TYPE,
// //         HeaderValue::from_static("application/json"),
// //     );

// //     Ok(response_with_json_content_type)
// // }

// // fn logout_handler(_:jwt_auth::jwt_middleware) -> Result<impl warp::Reply, Rejection> {
// //     let cookie_value = "token=; Path=/; Max-Age=-1; HttpOnly";

// //     let json_response = reply::json(&json!({
// //         "status": "success"
// //     }));

// //     let response_with_cookie = warp::reply::with_header(
// //         json_response,
// //         SET_COOKIE,
// //         HeaderValue::from_str(cookie_value).unwrap(),
// //     );

// //     Ok(response_with_cookie)
// // }

// // async fn get_me_handler(user_id: Uuid, pool: Pool<Postgres>) -> Result<impl Reply, Rejection> {
// //     let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
// //         .fetch_one(&pool)
// //         .await
// //         .unwrap();

// //     let json_response = json!({
// //         "status": "success",
// //         "data": json!({
// //             "user": filter_user_record(&user)
// //         })
// //     });

// //     Ok(warp::reply::json(&json_response))
// // }

// pub fn routes(
//     pool: Pool<Postgres>,
//     config: Config,
// ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
//     let register_user_handler = warp::path("api")
//         .and(warp::path("auth"))
//         .and(warp::path("register"))
//         .and(warp::post())
//         .and(warp::body::json())
//         .and(with_pool(pool.clone()))
//         .and_then(register_user_handler);

//     let login_user_handler = warp::path("api")
//         .and(warp::path("auth"))
//         .and(warp::path("login"))
//         .and(warp::post())
//         .and(warp::body::json())
//         .and(with_config(config.clone()))
//         .and(with_pool(pool.clone()))
//         .and_then(login_user_handler);

//     // let logout_handler = warp::path("api")
//     //     .and(warp::path("auth"))
//     //     .and(warp::path("logout"))
//     //     .and(warp::get())
//     //     .and(jwt_auth::jwt_middleware(config.clone(), None))
//     //     .and_then(logout_handler);

//     // let get_me_handler = warp::path("api")
//     //     .and(warp::path("users"))
//     //     .and(warp::path("me"))
//     //     .and(warp::get())
//     //     .and(jwt_auth::authenticate(config.clone(),  warp::header::value("Authorization")))
//     //     .and(with_pool(pool.clone()))
//     //     .and_then(get_me_handler);

//     register_user_handler
//         .or(login_user_handler)
//         // .or(logout_handler)
//         // .or(get_me_handler)
// }

// fn with_pool(
//     pool: Pool<Postgres>,
// ) -> impl Filter<Extract = (Pool<Postgres>,), Error = std::convert::Infallible> + Clone {
//     warp::any().map(move || pool.clone())
// }

// fn with_config(
//     config: Config,
// ) -> impl Filter<Extract = (Config,), Error = std::convert::Infallible> + Clone {
//     warp::any().map(move || config.clone())
// }

use chrono::{Duration, Utc};
use crate::HeaderValue;
use serde_json::json;
use cookie::Cookie;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::convert::Infallible;
use uuid::Uuid;
use warp::{
    http::header::SET_COOKIE, reject, reply, Filter, Rejection, Reply,
};

use crate::config::Config;
use crate::model::{TokenClaims, User};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ErrorResponse {
    status: String,
    message: String,
}

impl warp::reject::Reject for ErrorResponse {}

pub fn jwt_middleware(
    config: Config,
) -> impl Filter<Extract = (Uuid,), Error = Rejection> + Clone {
    Cookie ()
        .and(with_config(config))
        .and_then(|cookies: Vec<Cookie>, config: Config| async move {
            let token = extract_token_from_cookies(&cookies);
            match token {
                Ok(token) => match decode::<TokenClaims>(
                    &token,
                    &DecodingKey::from_secret(config.jwt_secret.as_ref()),
                    &Validation::default(),
                ) {
                    Ok(c) => {
                        let now = Utc::now();
                        let exp = c.claims.exp as i64;
                        if now.timestamp() < exp {
                            Ok(Uuid::parse_str(c.claims.sub.as_str()).unwrap())
                        } else {
                            Err(warp::reject::custom(ErrorResponse {
                                status: "fail".to_string(),
                                message: "Token expired".to_string(),
                            }))
                        }
                    }
                    Err(_) => Err(warp::reject::custom(ErrorResponse {
                        status: "fail".to_string(),
                        message: "Invalid token".to_string(),
                    })),
                },
                Err(_) => Err(warp::reject::custom(ErrorResponse {
                    status: "fail".to_string(),
                    message: "You are not logged in, please provide a token".to_string(),
                })),
            }
        })
}

async fn logout_handler(
    user_id: Uuid,
    pool: Pool<Postgres>,
    config: Config,
) -> Result<warp::reply::WithHeader<warp::reply::Json>, Rejection> {
    let cookie_value = format!("token=; Path=/; Max-Age=0; HttpOnly");

    // Delete the token from the database
    sqlx::query("DELETE FROM tokens WHERE user_id = $1")
        .bind(user_id.to_string())
        .execute(&pool)
        .await
        .map_err(|_| {
            warp::reject::custom(ErrorResponse {
                status: "error".to_string(),
                message: "Failed to log out".to_string(),
            })
        })?;

    let json_response = reply::json(&json!({
        "status": "success",
        "message": "Logged out successfully"
    }));

    let response_with_cookie = warp::reply::with_header(
        json_response,
        SET_COOKIE,
        HeaderValue::from_str(&cookie_value).unwrap(),
    );

    Ok(response_with_cookie)
}

// fn extract_token_from_cookies(cookies: &[Cookie]) -> Result<String, Infallible> {
//     for cookie in cookies {
//         if cookie.name() == "token" {
//             return Ok(cookie.value().to_string());
//         }
//     }
//     Err("Token not found in cookies".to_string())
// }
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

pub fn routes(
    pool: Pool<Postgres>,
    config: Config,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let logout_handler = warp::path("api")
        .and(warp::path("auth"))
        .and(warp::path("logout"))
        .and(warp::get())
        .and(jwt_middleware(config.clone()))
        .and(with_pool(pool.clone()))
        .and(with_config(config.clone()))
        .and_then(logout_handler);

    logout_handler
}