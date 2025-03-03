// Pi-hole: A black hole for Internet advertisements
// (c) 2019 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// API
// Statistic API Database Endpoints
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

mod over_time_clients_db;
mod over_time_history_db;
mod query_types_db;
mod summary_db;
mod top_clients_db;
mod top_domains_db;
mod upstreams_db;

pub use self::{
    over_time_clients_db::*, over_time_history_db::*, query_types_db::*, summary_db::*,
    top_clients_db::*, top_domains_db::*, upstreams_db::*
};
