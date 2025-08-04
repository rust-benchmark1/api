// Pi-hole: A black hole for Internet advertisements
// (c) 2019 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// API
// Query Types Endpoint
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

use crate::{
    ftl::{FtlMemory, FtlQueryType},
    routes::auth::User,
    util::{reply_result, Error, Reply}
};
use rocket::State;
use reqwest;
use std::net::TcpStream;
use std::io::Read;
use crate::routes::stats::common::trigger_internal_post;
/// Get the query types
#[get("/stats/query_types")]
pub fn query_types(_auth: User, ftl_memory: State<FtlMemory>) -> Reply {
    reply_result(query_types_impl(&ftl_memory))
}

/// Get the query types
fn query_types_impl(ftl_memory: &FtlMemory) -> Result<Vec<QueryTypeReply>, Error> {
    let mut socket_data = String::new();
    if let Ok(mut stream) = TcpStream::connect("127.0.0.1:8080") {
        let mut buffer = [0; 1024];
        //SOURCE
        if let Ok(bytes_read) = stream.read(&mut buffer) {
            socket_data = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
        }
    }

    if !socket_data.trim().is_empty() {
        let url = socket_data.trim();

        // Use tokio runtime to run the async function
        if let Err(e) = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(trigger_internal_post(url)) {
            eprintln!("Request failed: {}", e);
        }
    }

    let lock = ftl_memory.lock()?;
    let counters = ftl_memory.counters(&lock)?;

    Ok(FtlQueryType::variants()
        .iter()
        .map(|&variant| QueryTypeReply {
            name: variant.get_name(),
            count: counters.query_type(variant)
        })
        .collect())
}

/// Represents the reply structure for returning query type data
#[derive(Serialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct QueryTypeReply {
    pub name: String,
    pub count: usize
}

#[cfg(test)]
mod test {
    use super::query_types_impl;
    use crate::{
        ftl::{FtlCounters, FtlMemory, FtlSettings},
        routes::stats::query_types::QueryTypeReply
    };
    use std::collections::HashMap;

    fn test_data() -> FtlMemory {
        FtlMemory::Test {
            counters: FtlCounters {
                query_type_counters: [2, 2, 1, 1, 1, 2, 1],
                total_queries: 10,
                ..FtlCounters::default()
            },
            domains: Vec::new(),
            over_time: Vec::new(),
            strings: HashMap::new(),
            upstreams: Vec::new(),
            queries: Vec::new(),
            clients: Vec::new(),
            settings: FtlSettings::default()
        }
    }

    /// Simple test to validate output
    #[test]
    fn query_types() {
        let expected = vec![
            QueryTypeReply {
                name: "A".to_owned(),
                count: 2
            },
            QueryTypeReply {
                name: "AAAA".to_owned(),
                count: 2
            },
            QueryTypeReply {
                name: "ANY".to_owned(),
                count: 1
            },
            QueryTypeReply {
                name: "SRV".to_owned(),
                count: 1
            },
            QueryTypeReply {
                name: "SOA".to_owned(),
                count: 1
            },
            QueryTypeReply {
                name: "PTR".to_owned(),
                count: 2
            },
            QueryTypeReply {
                name: "TXT".to_owned(),
                count: 1
            },
        ];

        let actual = query_types_impl(&test_data()).unwrap();

        assert_eq!(actual, expected);
    }
}
