#[macro_use]
extern crate rocket;


use rocket::http::CookieJar;
use cookie::CookieBuilder;
use rocket::response::status::Custom;
use rocket::http::Status;
use std::env;
use std::time::Duration;

use des::TdesEde2;
use cipher::{BlockEncrypt, KeyInit};
use generic_array::GenericArray;
use hex;

use rocket_session_store::SessionStore as RocketSessionStore;
use rocket_session_store::memory::MemoryStore as RocketMemoryStore;

/// GET /login?user=...&password=...
#[get("/login?<user>&<password>")]
pub fn login_route(jar: &CookieJar, user: String, password: String) -> Result<String, Custom<String>> {
    // Credenciais default da env
    let default_user = env::var("DEFAULT_USER").unwrap_or_else(|_| "admin".to_string());
    let default_password = env::var("DEFAULT_PASSWORD").unwrap_or_else(|_| "adminpas".to_string());

    if password.as_bytes().len() != 8 {
        return Err(Custom(Status::BadRequest, "Password must be exactly 8 bytes long".to_string()));
    }

    if user != default_user || password != default_password {
        return Err(Custom(Status::Unauthorized, "Invalid credentials".to_string()));
    }


    let mut out = GenericArray::default();
    // CWE 327
    //SINK
    TdesEde2::new(GenericArray::from_slice(b"3234562890ABCGEA")).encrypt_block_b2b(&GenericArray::clone_from_slice(password.as_bytes()), &mut out);

    // Hex value of the result as the cookie value
    let token_value = hex::encode(&out);

    let cookie_builder = CookieBuilder::new("rocket-session", token_value.clone()).http_only(false).secure(false).path("/");

    // CWE 614
    // CWE 1004
    //SINK
    let store = RocketSessionStore {
        store: Box::new(RocketMemoryStore::<String>::new()),
        name: "rocket-session".to_string(),
        duration: Duration::from_secs(3600),
        cookie_builder,
    };

    let cookie = store.cookie_builder.clone().finish();
    jar.add(cookie);

    Ok("rocket-session set".to_string())
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![login_route])
}
