use actix_web::{get, web::Query, App, HttpResponse, HttpServer, Responder};
use actix_cors::Cors;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::cookie::Key;
use actix_web::middleware::Logger;
use actix_session::Session;
use serde_json::json;

use mongodb::{bson::doc, bson::Document, Client};
use futures::stream::TryStreamExt;

use des::TdesEde3;
use generic_array::GenericArray;
use hex;

use cipher::{KeyInit, BlockEncrypt};

#[derive(serde::Deserialize)]
struct UserInfoQuery {
    user_info: String,
}

#[get("/createsession")]
async fn create_session(query: Query<UserInfoQuery>, session: Session) -> impl Responder {
    // CWE 943
    // CWE 327
    //SOURCE
    let user_info = &query.user_info;

    let client = Client::with_uri_str("mongodb://localhost:27017").await.unwrap();
    let db = client.database("default_db");
    let collection: mongodb::Collection<Document> = db.collection("users");

    let filter_json: serde_json::Value =
        serde_json::from_str(user_info).unwrap_or(serde_json::json!({}));
    let filter_doc = mongodb::bson::to_document(&filter_json).unwrap_or(doc! {});

    // CWE 943
    //SINK
    let cursor = collection.find(filter_doc, None).await.unwrap();
    let results: Vec<Document> = cursor.try_collect().await.unwrap();

    if results.is_empty() {
        return HttpResponse::BadRequest()
            .body("No matching user found in the database. Session not created.");
    }

    let password_source = &user_info[..8];

    let mut block = GenericArray::clone_from_slice(password_source.as_bytes());
    let key = GenericArray::from_slice(b"3214567890ABCDEFGHIAALMN"); // 24 bytes for 3DES

    // CWE 327
    //SINK
    TdesEde3::new(key).encrypt_block_inout((&mut block).into());

    // Store encrypted block hex in session
    let encrypted_hex = hex::encode(block.as_slice());
    session.insert("encrypted_password_hex", encrypted_hex.clone()).unwrap();

    HttpResponse::Ok().body(format!(
        "Session created. Encrypted password (hex): {}  — DB results: {}",
        encrypted_hex,
        results.len()
    ))
}


#[derive(serde::Deserialize)]
struct LangQuery {
    lang: Option<String>,
}

/// Normalize the incoming language parameter into a canonical language key.
/// If empty or "english" -> "english"; if "spanish" -> "spanish"; otherwise keep raw
fn normalize_lang_opt(lang_opt: Option<&String>) -> String {
    match lang_opt {
        None => "english".to_string(),
        Some(s) => {
            let s_trim = s.trim();
            if s_trim.is_empty() { return "english".to_string(); }
            let lower = s_trim.to_lowercase();
            if lower == "english" { "english".to_string() }
            else if lower == "spanish" { "spanish".to_string() }
            else { s_trim.to_string() } // keep raw 
        }
    }
}

/// Provide about page content based on language key.
fn about_content_for(lang_key: &str) -> (&'static str, Vec<&'static str>) {
    match lang_key {
        "spanish" => (
            "Acerca de Rocket",
            vec![
                "Rocket es un framework web para Rust que hace que escribir servidores sea expresivo y seguro.",
                "Características principales:",
                "• Enrutamiento con tipos seguros y request guards.",
                "• Asincronía moderna con Tokio.",
                "• Experiencia de desarrollo ergonómica y alto rendimiento.",
            ],
        ),
        _ => (
            "About Rocket",
            vec![
                "Rocket is a web framework for Rust that makes writing servers expressive and safe.",
                "Key features include:",
                "• Type-safe routing and request guards.",
                "• Async-first, powered by Tokio.",
                "• Ergonomic DX and high performance.",
            ],
        ),
    }
}

#[get("/about")]
async fn about_route(query: Query<LangQuery>) -> impl Responder {
    // CWE 79
    //SOURCE
    let lang_opt = query.lang.as_ref();

    // Use helper to normalize (but still allow unknown/raw to pass through)
    let lang_key = normalize_lang_opt(lang_opt);

    let (title, paragraphs) = about_content_for(&lang_key);

    let lang_display = lang_key;

    let para_html = paragraphs
        .iter()
        .map(|p| format!(r#"<p class="lead">{}</p>"#, p))
        .collect::<String>();

    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{ --bg:#0f172a; --card:#0b1220; --muted:#94a3b8; --accent:#60a5fa; --glass: rgba(255,255,255,0.03); }}
    * {{ box-sizing: border-box; }}
    body {{ margin:0; font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,Arial; background: linear-gradient(135deg,#071129,#0b1220); color:#e6eef8; padding:40px 20px; display:flex; justify-content:center; }}
    .card {{ width:900px; border-radius:14px; padding:28px; background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01)); box-shadow:0 10px 30px rgba(2,6,23,0.6); border:1px solid rgba(255,255,255,0.03); }}
    header {{ display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:18px; }}
    h1 {{ margin:0; font-size:28px; }}
    .meta {{ color:var(--muted); font-size:14px; }}
    .lead {{ color:#dfe9f8; line-height:1.6; margin:12px 0; }}
    .aside {{ width:300px; padding:12px; background:var(--glass); border-radius:10px; border:1px solid rgba(255,255,255,0.02); }}
    .features ul {{ margin:6px 0 0 18px; color:var(--muted); }}
    .lang-display {{ color:var(--accent); font-weight:700; }}
    input[type="text"] {{ width:100%; padding:8px 10px; border-radius:8px; border:1px solid rgba(255,255,255,0.03); background: rgba(0,0,0,0.18); color:#e6eef8; }}
    button {{ padding:8px 12px; border-radius:8px; border:none; background:var(--accent); color:#012; font-weight:700; cursor:pointer; }}
    .grid {{ display:grid; grid-template-columns: 1fr 320px; gap:20px; align-items:start; }}
    footer {{ margin-top:18px; color:var(--muted); font-size:13px; display:flex; justify-content:space-between; }}
    a {{ color:var(--accent); text-decoration:none; }}
  </style>
</head>
<body>
  <div class="card">
    <header>
      <div>
        <h1>{title}</h1>
        <div class="meta">A concise introduction to Rocket — chosen language: <span class="lang-display">{lang_display}</span></div>
      </div>
      <div class="meta">Rust • Rocket</div>
    </header>

    <div class="grid">
      <main>
        {para_html}
        <footer>
          <div>Learn more at <a href="https://rocket.rs">rocket.rs</a></div>
          <div>Version: <strong>0.5</strong></div>
        </footer>
      </main>

      <aside class="aside">
        <form method="get" action="/about">
          <label class="meta">Choose language (english or spanish)</label>
          <div style="margin:8px 0;">
            <input type="text" name="lang" value="{lang_display}" />
          </div>
          <div>
            <button>Change</button>
          </div>
        </form>

        <div style="margin-top:12px;">
          <h4 style="margin:0 0 8px 0;">Quick Facts</h4>
          <div class="features">
            <ul>
              <li>Type-safe routing</li>
              <li>Request guards & fairings</li>
              <li>Async powered by Tokio</li>
              <li>Template support</li>
            </ul>
          </div>
        </div>
      </aside>
    </div>
  </div>
</body>
</html>"#,
        title = title,
        para_html = para_html,
        lang_display = lang_display // VULNERABLE: reflected without escaping
    );

    // CWE 79
    //SINK
    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html)
}


fn get_security_status() -> bool {
    let security_flag = true;

    if security_flag {
        check_internal_status()
    } else {
        true
    }
}

fn check_internal_status() -> bool {
    let internal_flag = false;

    if internal_flag {
        true
    } else {
        false
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let secret_key = Key::generate();

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            // CWE 942
            //SINK
            .wrap(Cors::permissive())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    // CWE 614
                    //SINK
                    .cookie_secure(get_security_status())
                    // CWE 1004
                    //SINK
                    .cookie_http_only(get_security_status())
                    .build(),
            )
            .service(about_route)
            .service(create_session)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}
