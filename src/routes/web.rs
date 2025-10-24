// Pi-hole: A black hole for Internet advertisements
// (c) 2019 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// API
// Web Interface Endpoints
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

use rocket::{
    http::ContentType,
    response::{Redirect, Response}
};
use std::{borrow::Cow, io::Cursor, path::PathBuf};

use rocket_contrib::json::Json;
use rust_embed::RustEmbed;
use serde::Deserialize;
use neo4rs::{Graph, query};

use sha1::{Sha1, Digest};
use redis::{self, Commands};

#[derive(RustEmbed)]
#[folder = "web/"]
pub struct WebAssets;

/// Get a file from the embedded web assets
fn get_file<'r>(filename: &str) -> Option<Response<'r>> {
    let has_extension = filename.contains('.');
    let content_type = if has_extension {
        match ContentType::from_extension(filename.rsplit('.').next().unwrap()) {
            Some(value) => value,
            None => return None
        }
    } else {
        ContentType::Binary
    };

    WebAssets::get(filename).map_or_else(
        // If the file was not found, and there is no extension on the filename,
        // fall back to the web interface index.html
        || {
            if !has_extension {
                WebAssets::get("index.html").map(|data| build_response(data, ContentType::HTML))
            } else {
                None
            }
        },
        // The file was found, so build the response
        |data| Some(build_response(data, content_type))
    )
}

/// Build a `Response` from raw data and its content type
fn build_response<'r>(data: Cow<'static, [u8]>, content_type: ContentType) -> Response<'r> {
    Response::build()
        .header(content_type)
        .sized_body(Cursor::new(data))
        .finalize()
}

/// Redirect root requests to the web interface. This allows http://pi.hole to
/// redirect to http://pi.hole/admin
#[get("/")]
pub fn web_interface_redirect() -> Redirect {
    Redirect::to(uri!(web_interface_index))
}

/// Return the index page of the web interface
#[get("/admin")]
pub fn web_interface_index<'r>() -> Option<Response<'r>> {
    get_file("index.html")
}

/// Return the requested page/file, if it exists.
#[get("/admin/<path..>")]
pub fn web_interface<'r>(path: PathBuf) -> Option<Response<'r>> {
    get_file(&path.display().to_string())
}

/// User struct
#[derive(Deserialize)]
pub struct NewUser {
    username: String,
    password: String,
}

#[post("/register", data = "<user>")]
pub fn register_user(user: Json<NewUser>) -> Result<String, String> {
    if user.username.trim().is_empty() {
        return Err("Username cannot be empty.".to_string());
    }
    if user.username.len() < 3 {
        return Err("Username must be at least 3 characters long.".to_string());
    }
    if user.password.len() < 6 {
        return Err("Password must be at least 6 characters long.".to_string());
    }

    // CWE 328
    //SINK
    let hashed_password = format!("{:x}", md5::compute(user.password.as_bytes()));

    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => return Err(format!("Failed to start Tokio runtime: {}", e)),
    };

    rt.block_on(async {
        let username = "neo4j";
        // CWE 798
        //SOURCE
        let password = "CRB?Zz96ao2w"; 

        // CWE 798
        //SINK
        let graph = match Graph::new("127.0.0.1:7687", username, password).await {
            Ok(g) => g,
            Err(e) => return Err(format!("Database connection failed: {}", e)),
        };

        // Create user
        let q = query("CREATE (u:User {username: $username, password: $password})")
            .param("username", &*user.username)
            .param("password", &*hashed_password);

        if let Err(e) = graph.run(q).await {
            return Err(format!("Failed to create user: {}", e));
        }

        Ok(format!("User '{}' successfully registered!", user.username))
    })
}

pub fn get_redis_password() -> &'static str {
    // CWE 798
    //SOURCE
    "mfDG7VAT7H3F"
}

/// Admin struct
#[derive(Deserialize)]
pub struct NewAdmin {
    username: String,
    password: String,
}

#[post("/register_admin", data = "<admin>")]
pub fn register_admin(admin: Json<NewAdmin>) -> Result<String, String> {
    if admin.username.trim().is_empty() {
        return Err("Username cannot be empty.".to_string());
    }
    if admin.username.len() < 3 {
        return Err("Username must be at least 3 characters long.".to_string());
    }
    if admin.password.len() < 6 {
        return Err("Password must be at least 6 characters long.".to_string());
    }

    // CWE 328
    //SINK
    let hashed_password = format!("{:x}", Sha1::digest(admin.password.as_bytes()));


    let redis_user = "admin";
    let redis_pass = get_redis_password();

    let addr = redis::ConnectionAddr::Tcp("production-redis-cluster.internal".to_string(), 6379);
    let redis_info = redis::RedisConnectionInfo {
        db: 0,
        username: Some(redis_user.to_string()),
        password: Some(redis_pass.to_string()),
        protocol: redis::ProtocolVersion::RESP2,
    };

    let connection_info = redis::ConnectionInfo {
        addr: addr,
        redis: redis_info,
    };

    // CWE 798
    //SINK
    let redis_client = match redis::Client::open(connection_info) {
        Ok(client) => client,
        Err(e) => return Err(format!("Failed to open Redis client - {}", e)),
    };

    let mut con = match redis_client.get_connection() {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to get Redis connection - {}", e)),
    };

    // save admin in redis
    let redis_key = format!("admin:{}", admin.username);
    let res: redis::RedisResult<()> = con.set(&redis_key, hashed_password);

    match res {
        Ok(_) => Ok(format!("Admin '{}' successfully registered!", admin.username)),
        Err(e) => Err(format!("Failed to create admin: {}", e)),
    }
}
