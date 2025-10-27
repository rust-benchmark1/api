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

use rocket::form::Form;
use rocket::response::content::RawHtml;
use std::borrow::Cow;

use rocket::serde::json::Json;
use rocket::serde::json::Value;

use mongodb::{bson::{doc, Document}, Client};

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

fn validate_no_dangerous_operators(filter: &str) -> String {
    let lower = filter.to_lowercase();
    if lower.contains("$where") || lower.contains("\"$where\"") {
        eprintln!("validate_no_dangerous_operators: found '$where' token (suspicious)");
    }
    if lower.contains("$eval") || lower.contains("\"$eval\"") {
        eprintln!("validate_no_dangerous_operators: found '$eval' token (suspicious)");
    }
    filter.to_string()
}

async fn mongodb_find_one(filter: String) -> Json<rocket::serde::json::Value> {
    let client = Client::with_uri_str("mongodb://localhost:28000").await.unwrap();
    let db = client.database("default_db");
    let collection: mongodb::Collection<Document> = db.collection("search_configs");
    
    let filter_json: rocket::serde::json::Value = rocket::serde::json::from_str(&filter)
        .unwrap_or(rocket::serde::json::json!({}));
    let filter_doc = mongodb::bson::to_document(&filter_json).unwrap_or(doc! {});
    // CWE 943
    //SINK
    let result = collection.find_one(filter_doc, None).await.unwrap();
    
    Json(rocket::serde::json::json!({
        "filter": filter,
        "result": result
    }))
}


#[derive(FromForm)]
pub struct ConfigQuery {
    pub filter: Option<String>,
}

#[get("/configs?<filter>")]
pub async fn list_configs(filter: Option<String>) -> RawHtml<String> {
    // CWE 943
    //SOURCE
    let search_text = filter.clone().unwrap_or_else(|| "".to_string());

    let validated_text = validate_no_dangerous_operators(&search_text);

    let mongo_result_json = mongodb_find_one(validated_text.clone()).await;
    let mongo_result_pretty = format!("{:#}", mongo_result_json.0);

    // store in process environment
    std::env::set_var("LAST_MONGO_RESULT", &mongo_result_pretty);

    let configs = vec![
        "database_url=postgres://localhost:5432",
        "cache_enabled=true",
        "api_key=12345-ABCDE",
        "feature_x_enabled=false",
        "log_level=debug",
        "max_connections=100",
    ];

    // CWE 79
    //SOURCE
    let filter_text = filter.unwrap_or_else(|| "".to_string());

    let filtered: Vec<&str> = if filter_text.is_empty() {
        configs.iter().map(|s| *s).collect()
    } else {
        configs
            .iter()
            .filter(|c| c.contains(&filter_text))
            .map(|s| *s)
            .collect()
    };

    let html = format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Available Configurations</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #74ABE2, #5563DE);
                    color: #fff;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    min-height: 100vh;
                    margin: 0;
                    padding: 2rem;
                }}
                h1 {{
                    margin-bottom: 1rem;
                    text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
                }}
                form {{
                    margin-bottom: 2rem;
                }}
                input[type="text"] {{
                    padding: 0.6rem 1rem;
                    border: none;
                    border-radius: 20px;
                    width: 240px;
                    outline: none;
                }}
                button {{
                    padding: 0.6rem 1.2rem;
                    border: none;
                    border-radius: 20px;
                    background-color: #fff;
                    color: #5563DE;
                    cursor: pointer;
                    font-weight: bold;
                    margin-left: 0.5rem;
                    transition: background 0.3s;
                }}
                button:hover {{
                    background-color: #e0e0e0;
                }}
                ul {{
                    list-style-type: none;
                    background: rgba(255,255,255,0.1);
                    border-radius: 10px;
                    padding: 1rem 2rem;
                    box-shadow: 0 4px 15px rgba(0,0,0,0.2);
                }}
                li {{
                    padding: 0.5rem 0;
                    border-bottom: 1px solid rgba(255,255,255,0.2);
                }}
                li:last-child {{
                    border-bottom: none;
                }}
                .filter-info {{
                    margin-bottom: 1rem;
                    font-style: italic;
                    opacity: 0.9;
                }}
            </style>
        </head>
        <body>
            <h1>Available Configurations</h1>
            <form method="get" action="/configs">
                <input type="text" name="filter" placeholder="Filter configs..." value="{filter_text}">
                <button type="submit">Search</button>
            </form>
            <div class="filter-info">Showing results for filter: <b>{filter_text}</b></div>
            <ul>
                {items}
            </ul>
        </body>
        </html>
        "#,
        filter_text = filter_text,
        items = filtered
            .iter()
            .map(|c| format!("<li>{}</li>", c))
            .collect::<Vec<String>>()
            .join("")
    );

    // CWE 79
    //SINK
    RawHtml(html)
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![login_route, list_configs])
}
