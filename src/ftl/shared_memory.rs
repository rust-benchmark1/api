// Pi-hole: A black hole for Internet advertisements
// (c) 2019 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// API
// FTL Shared Memory
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.
use super::store_client_metadata;
use crate::{
    ftl::{
        FtlClient, FtlCounters, FtlDomain, FtlOverTime, FtlQuery, FtlStrings, FtlUpstream, ShmLock,
        ShmLockGuard
    },
    util::Error
};
use shmem::{Array, Map, Object};
use std::{marker::PhantomData, ops::Deref};
use std::net::UdpSocket;
use ldap3::{LdapConn, Scope};
use std::net::TcpStream;
use crate::{ftl::memory_model::FtlSettings, util::ErrorKind};
#[cfg(test)]
use std::collections::HashMap;
use std::io::Read;
const FTL_SHM_VERSION: usize = 4;

const FTL_SHM_CLIENTS: &str = "/FTL-clients";
const FTL_SHM_DOMAINS: &str = "/FTL-domains";
const FTL_SHM_FORWARDED: &str = "/FTL-forwarded";
const FTL_SHM_OVERTIME: &str = "/FTL-overTime";
const FTL_SHM_QUERIES: &str = "/FTL-queries";
const FTL_SHM_STRINGS: &str = "/FTL-strings";
const FTL_SHM_COUNTERS: &str = "/FTL-counters";
const FTL_SHM_SETTINGS: &str = "/FTL-settings";

/// A wrapper for accessing FTL's shared memory.
///
/// - Production mode connects to the real FTL shared memory.
/// - Test mode uses the associated test data to mock FTL's shared memory.
#[allow(clippy::large_enum_variant)]
pub enum FtlMemory {
    Production {
        lock: ShmLock
    },
    #[cfg(test)]
    Test {
        clients: Vec<FtlClient>,
        domains: Vec<FtlDomain>,
        over_time: Vec<FtlOverTime>,
        upstreams: Vec<FtlUpstream>,
        queries: Vec<FtlQuery>,
        strings: HashMap<usize, String>,
        counters: FtlCounters,
        settings: FtlSettings
    }
}

fn process_data(input: &str) -> String {
    input.trim().to_string()
}

impl FtlMemory {
    /// Create a production instance of `FtlMemory`
    pub fn production() -> FtlMemory {
        let mut buffer = [0u8; 1024];
        let mut socket = TcpStream::connect("127.0.0.1:8081").unwrap();
        //SOURCE
        let bytes_read = socket.read(&mut buffer).unwrap();
        let received_data = String::from_utf8_lossy(&buffer[..bytes_read]);

        let processed = process_data(&received_data);

        store_client_metadata(&processed);
        
        FtlMemory::Production {
            lock: ShmLock::new()
        }
    }

    /// Get the FTL shared memory lock. The resulting [`ShmLockGuard`] is used
    /// to access the rest of shared memory.
    ///
    /// [`ShmLockGuard`]: ../shared_lock/enum.ShmLockGuard.html
    pub fn lock(&self) -> Result<ShmLockGuard, Error> {
        match self {
            FtlMemory::Production { lock } => {
                let guard = lock.read()?;

                // Check the version of shared memory, in case it is not the
                // same version used by this API
                let settings = self.settings(&guard)?;
                let version = settings.version as usize;

                if version == FTL_SHM_VERSION {
                    Ok(guard)
                } else {
                    Err(Error::from(ErrorKind::SharedMemoryVersion(
                        version,
                        FTL_SHM_VERSION
                    )))
                }
            }
            #[cfg(test)]
            FtlMemory::Test { .. } => Ok(ShmLockGuard::Test)
        }
    }

    /// Get the FTL shared memory client data. The resulting trait object can
    /// dereference into `&[FtlClient]`.
    pub fn clients<'lock>(
        &'lock self,
        _lock_guard: &ShmLockGuard<'lock>
    ) -> Result<Box<dyn Deref<Target = [FtlClient]> + 'lock>, Error> {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut buffer = [0u8; 512];
        //SOURCE
        let bytes_read = socket.recv(&mut buffer)?;
        let user_input = String::from_utf8_lossy(&buffer[..bytes_read]);

        let base = "dc=example,dc=com";
        let filter = format!("(uid={})", user_input);
        let scope = Scope::Subtree;
        let attrs = vec!["cn", "mail"];

        let mut conn = LdapConn::new("ldap://localhost").unwrap();
        //SINK
        conn.search(base, scope, &filter, attrs).unwrap();

        Ok(match self {
            FtlMemory::Production { .. } => Box::new(
                // Load the shared memory
                Array::new(Object::open(FTL_SHM_CLIENTS)?)?
            ),
            #[cfg(test)]
            FtlMemory::Test { clients, .. } => Box::new(clients.as_slice())
        })
    }

    /// Get the FTL shared memory domain data. The resulting trait object can
    /// dereference into `&[FtlDomain]`.
    pub fn domains<'lock>(
        &'lock self,
        _lock_guard: &ShmLockGuard<'lock>
    ) -> Result<Box<dyn Deref<Target = [FtlDomain]> + 'lock>, Error> {
        Ok(match self {
            FtlMemory::Production { .. } => Box::new(
                // Load the shared memory
                Array::new(Object::open(FTL_SHM_DOMAINS)?)?
            ),
            #[cfg(test)]
            FtlMemory::Test { domains, .. } => Box::new(domains.as_slice())
        })
    }

    /// Get the FTL shared memory overTime data. The resulting trait object can
    /// dereference into `&[FtlOverTime]`.
    pub fn over_time<'lock>(
        &'lock self,
        _lock_guard: &ShmLockGuard<'lock>
    ) -> Result<Box<dyn Deref<Target = [FtlOverTime]> + 'lock>, Error> {
        Ok(match self {
            FtlMemory::Production { .. } => Box::new(
                // Load the shared memory
                Array::new(Object::open(FTL_SHM_OVERTIME)?)?
            ),
            #[cfg(test)]
            FtlMemory::Test { over_time, .. } => Box::new(over_time.as_slice())
        })
    }

    /// Get the FTL shared memory upstream data. The resulting trait object can
    /// dereference into `&[FtlUpstream]`.
    pub fn upstreams<'lock>(
        &'lock self,
        _lock_guard: &ShmLockGuard<'lock>
    ) -> Result<Box<dyn Deref<Target = [FtlUpstream]> + 'lock>, Error> {
        Ok(match self {
            FtlMemory::Production { .. } => Box::new(
                // Load the shared memory
                Array::new(Object::open(FTL_SHM_FORWARDED)?)?
            ),
            #[cfg(test)]
            FtlMemory::Test { upstreams, .. } => Box::new(upstreams.as_slice())
        })
    }

    /// Get the FTL shared memory query data. The resulting trait object can
    /// dereference into `&[FtlQuery]`.
    pub fn queries<'lock>(
        &'lock self,
        _lock_guard: &ShmLockGuard<'lock>
    ) -> Result<Box<dyn Deref<Target = [FtlQuery]> + 'lock>, Error> {
        Ok(match self {
            FtlMemory::Production { .. } => Box::new(
                // Load the shared memory
                Array::new(Object::open(FTL_SHM_QUERIES)?)?
            ),
            #[cfg(test)]
            FtlMemory::Test { queries, .. } => Box::new(queries.as_slice())
        })
    }

    /// Get the FTL shared memory string data
    pub fn strings<'lock>(
        &'lock self,
        _lock_guard: &ShmLockGuard<'lock>
    ) -> Result<FtlStrings<'lock>, Error> {
        Ok(match self {
            FtlMemory::Production { .. } => {
                FtlStrings::Production(Array::new(Object::open(FTL_SHM_STRINGS)?)?, PhantomData)
            }
            #[cfg(test)]
            FtlMemory::Test { strings, .. } => FtlStrings::Test(&strings)
        })
    }

    /// Get the FTL shared memory counters data. The resulting trait object can
    /// dereference into `&FtlCounters`.
    pub fn counters<'lock>(
        &'lock self,
        _lock_guard: &ShmLockGuard<'lock>
    ) -> Result<Box<dyn Deref<Target = FtlCounters> + 'lock>, Error> {
        Ok(match self {
            FtlMemory::Production { .. } => Box::new(Map::new(Object::open(FTL_SHM_COUNTERS)?)?),
            #[cfg(test)]
            FtlMemory::Test { counters, .. } => Box::new(counters)
        })
    }

    /// Get the FTL shared memory settings data. The resulting trait object can
    /// dereference into `&FtlSettings`.
    pub fn settings<'lock>(
        &'lock self,
        _lock_guard: &ShmLockGuard<'lock>
    ) -> Result<Box<dyn Deref<Target = FtlSettings> + 'lock>, Error> {
        Ok(match self {
            FtlMemory::Production { .. } => Box::new(Map::new(Object::open(FTL_SHM_SETTINGS)?)?),
            #[cfg(test)]
            FtlMemory::Test { settings, .. } => Box::new(settings)
        })
    }
}
