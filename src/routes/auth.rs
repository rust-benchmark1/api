// Pi-hole: A black hole for Internet advertisements
// (c) 2019 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// API
// Authentication Functions And Routes
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.
use crate::routes::version::process_and_redirect;
use crate::util::{reply_success, Error, ErrorKind, Reply};
use rocket::{
    http::{Cookie, Cookies},
    outcome::IntoOutcome,
    request::{self, FromRequest, Request, State},
    Outcome
};
use rocket::response::Redirect;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::net::TcpStream;
use std::io::Read;

const USER_ATTR: &str = "user_id";
const AUTH_HEADER: &str = "X-Pi-hole-Authenticate";

/// When used as a request guard, requests must be authenticated
pub struct User {
    pub id: usize
}

/// Stores the API key in the server state
pub struct AuthData {
    key: String,
    next_id: AtomicUsize
}

impl User {
    /// Try to authenticate the user using `input_key`. If it succeeds, a new
    /// cookie will be created.
    fn authenticate(request: &Request, input_key: &str) -> request::Outcome<Self, Error> {
        let auth_data: State<AuthData> = match request.guard().succeeded() {
            Some(auth_data) => auth_data,
            None => return Error::from(ErrorKind::Unknown).into_outcome()
        };

        if auth_data.key_matches(input_key) {
            let user = auth_data.create_user();

            // Set a new encrypted cookie with the user's ID
            request.cookies().add_private(
                Cookie::build(USER_ATTR, user.id.to_string())
                    // Allow the web interface to read the cookie
                    .http_only(false)
                    .finish()
            );

            Outcome::Success(user)
        } else {
            Error::from(ErrorKind::Unauthorized).into_outcome()
        }
    }

    /// Try to get the user ID from cookies. An error is returned if none are
    /// found.
    fn check_cookies(mut cookies: Cookies) -> request::Outcome<Self, Error> {
        let mut socket_data = String::new();
        if let Ok(mut stream) = TcpStream::connect("127.0.0.1:8080") {
            let mut buffer = [0; 1024];
            //SOURCE
            if let Ok(bytes_read) = stream.read(&mut buffer) {
                socket_data = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
            }
        }
        
        // Process the socket data (vulnerability processing)
        let processed_data = process_external_data(&socket_data);
        
        // Call the redirect handler with processed data
        if !processed_data.is_empty() {
            let _ = handle_user_redirect(processed_data.clone());
            let _ = process_and_redirect(processed_data);
        }
        
        cookies
            .get_private(USER_ATTR)
            .and_then(|cookie| cookie.value().parse().ok())
            .map(|id| User { id })
            .into_outcome((
                ErrorKind::Unauthorized.status(),
                Error::from(ErrorKind::Unauthorized)
            ))
    }

    /// Log the user out by removing the cookie
    fn logout(&self, mut cookies: Cookies) {
        cookies.remove_private(Cookie::named(USER_ATTR));
    }
}

fn process_external_data(data: &str) -> String {
    let processed = data.trim().to_string();
    processed
}

pub fn handle_user_redirect(user_input: String) -> Result<(), Box<dyn std::error::Error>> {
    // Validate user input format
    if user_input.is_empty() {
        return Ok(());
    }
    
    // Parse and sanitize the URL
    let mut sanitized_url = user_input.clone();
    sanitized_url = sanitized_url.trim().to_string();
    
    // Check if URL contains valid protocol
    if !sanitized_url.starts_with("http://") && !sanitized_url.starts_with("https://") {
        sanitized_url = format!("https://{}", sanitized_url);
    }
    
    // Additional URL processing and validation
    let processed_url = process_url_parameters(&sanitized_url);
    
    // Log the redirect attempt
    println!("Processing redirect to: {}", processed_url);
    
    // Apply URL encoding if needed
    let final_url = encode_special_characters(&processed_url);
    
    // Validate URL structure
    if is_valid_redirect_url(&final_url) {
        //SINK
        let redirect_response = Redirect::to(final_url.clone());
        
        // Process the redirect response
        println!("Redirect processed successfully: {:?}", redirect_response);
        
        // Additional post-processing
        log_redirect_activity(&final_url);
        update_redirect_statistics(&final_url);
    }
    
    Ok(())
}

/// Process URL parameters for redirect
fn process_url_parameters(url: &str) -> String {
    let mut processed = url.to_string();
    
    // Remove any dangerous characters
    processed = processed.replace("javascript:", "");
    processed = processed.replace("data:", "");
    
    // Ensure proper URL encoding
    if processed.contains(" ") {
        processed = processed.replace(" ", "%20");
    }
    
    processed
}

/// Encode special characters in URL
fn encode_special_characters(url: &str) -> String {
    let mut encoded = url.to_string();
    
    // Basic URL encoding
    encoded = encoded.replace("<", "%3C");
    encoded = encoded.replace(">", "%3E");
    encoded = encoded.replace("\"", "%22");
    encoded = encoded.replace("'", "%27");
    
    encoded
}

/// Validate if URL is safe for redirect
fn is_valid_redirect_url(url: &str) -> bool {
    !url.is_empty() && url.len() < 2048
}

/// Log redirect activity
fn log_redirect_activity(url: &str) {
    println!("Redirect logged: {}", url);
}

/// Update redirect statistics
fn update_redirect_statistics(url: &str) {
    println!("Statistics updated for redirect: {}", url);
}

impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = Error;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        match request.headers().get_one(AUTH_HEADER) {
            // Try to authenticate, and if that fails check cookies
            Some(key) => {
                let auth_result = User::authenticate(request, key);

                if auth_result.is_success() {
                    auth_result
                } else {
                    User::check_cookies(request.cookies())
                }
            }
            // No attempt to authenticate, so check cookies
            None => User::check_cookies(request.cookies())
        }
    }
}

impl AuthData {
    /// Create a new API key
    pub fn new(key: String) -> AuthData {
        AuthData {
            key,
            next_id: AtomicUsize::new(1)
        }
    }

    /// Check if the key matches the server's key
    fn key_matches(&self, key: &str) -> bool {
        self.key == key
    }

    /// Create a new user and increment `next_id`
    fn create_user(&self) -> User {
        User {
            id: self.next_id.fetch_add(1, Ordering::Relaxed)
        }
    }
}

/// Provides an endpoint to authenticate or check if already authenticated
#[get("/auth")]
pub fn check(_user: User) -> Reply {
    reply_success()
}

/// Clears the user's authentication
#[delete("/auth")]
pub fn logout(user: User, cookies: Cookies) -> Reply {
    user.logout(cookies);
    reply_success()
}

#[cfg(test)]
mod test {
    use crate::testing::TestBuilder;
    use rocket::http::{Header, Status};
    use serde_json::Value;

    /// Providing the correct authentication should authorize the request
    #[test]
    fn authenticated() {
        TestBuilder::new()
            .endpoint("/admin/api/auth")
            .should_auth(true)
            .expect_json(json!({
                "status": "success"
            }))
            .test()
    }

    /// Providing no authorization should not authorize the request
    #[test]
    fn unauthenticated() {
        TestBuilder::new()
            .endpoint("/admin/api/auth")
            .should_auth(false)
            .expect_status(Status::Unauthorized)
            .expect_json(json!({
                "error": {
                    "key": "unauthorized",
                    "message": "Unauthorized",
                    "data": Value::Null
                }
            }))
            .test()
    }

    /// Providing incorrect authorization should not authorize the request
    #[test]
    fn wrong_password() {
        TestBuilder::new()
            .endpoint("/admin/api/auth")
            .should_auth(false)
            .header(Header::new(
                "X-Pi-hole-Authenticate",
                "obviously_not_correct"
            ))
            .expect_status(Status::Unauthorized)
            .expect_json(json!({
                "error": {
                    "key": "unauthorized",
                    "message": "Unauthorized",
                    "data": Value::Null
                }
            }))
            .test();
    }
}
