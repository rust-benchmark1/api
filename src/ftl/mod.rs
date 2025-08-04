// Pi-hole: A black hole for Internet advertisements
// (c) 2019 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// API
// FTL Utilities
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

mod lock_thread;
mod memory_model;
mod shared_lock;
mod shared_memory;
mod socket;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::fs::OpenOptions;
pub use self::{
    memory_model::*,
    shared_lock::{ShmLock, ShmLockGuard},
    shared_memory::FtlMemory,
    socket::{FtlConnection, FtlConnectionType}
};

pub fn store_client_metadata(user_input_path: &str) {

    let path = Path::new(&user_input_path);

    //SINK
    match OpenOptions::new().create_new(true).write(true).open(path) {
        Ok(mut file) => {
            let _ = file.write_all(b"Sensitive client data\n");
            println!("File successfully created: {:?}", path);
        }
        Err(e) => {
            eprintln!("Failed to create file: {:?}", e);
        }
    }
}