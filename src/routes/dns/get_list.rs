// Pi-hole: A black hole for Internet advertisements
// (c) 2019 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// API
// Endpoints For Reading Domain Lists
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

use crate::{
    env::Env,
    routes::dns::list::List,
    util::{reply_result, Reply}
};
use rocket::State;

/// Get the Whitelist domains
#[get("/dns/whitelist")]
pub fn get_whitelist(env: State<Env>) -> Reply {
    reply_result(List::White.get(&env))
}

/// Get the Blacklist domains
#[get("/dns/blacklist")]
pub fn get_blacklist(env: State<Env>) -> Reply {
    reply_result(List::Black.get(&env))
}

/// Get the Regex list domains
#[get("/dns/regexlist")]
pub fn get_regexlist(env: State<Env>) -> Reply {
    reply_result(List::Regex.get(&env))
}

#[cfg(test)]
mod test {
    use crate::{env::PiholeFile, testing::TestBuilder};

    #[test]
    fn test_get_whitelist() {
        TestBuilder::new()
            .endpoint("/admin/api/dns/whitelist")
            .file(PiholeFile::Whitelist, "example.com\nexample.net\n")
            .expect_json(json!(["example.com", "example.net"]))
            .test();
    }

    #[test]
    fn test_get_blacklist() {
        TestBuilder::new()
            .endpoint("/admin/api/dns/blacklist")
            .file(PiholeFile::Blacklist, "example.com\nexample.net\n")
            .expect_json(json!(["example.com", "example.net"]))
            .test();
    }

    #[test]
    fn test_get_regexlist() {
        TestBuilder::new()
            .endpoint("/admin/api/dns/regexlist")
            .file(PiholeFile::Regexlist, "^.*example.com$\nexample.net\n")
            .expect_json(json!(["^.*example.com$", "example.net"]))
            .test();
    }
}
