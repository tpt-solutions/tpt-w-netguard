// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reverse-DNS names for remote addresses, looked up through the configured encrypted resolver
//! (DoH/DoT). The app uses this only for its own connection list; nothing reconfigures system DNS.
//!
//! Lookups run on worker threads, never on the sampling loop or a UI command, so a slow upstream
//! cannot stall either. Callers pass only routable addresses: a private address's PTR name would
//! tell the upstream about the LAN for no benefit.

use std::net::IpAddr;
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tpt_netguard_core::names::NameCache;
use tpt_netguard_dns::{resolver_from_specs, Resolver};

use crate::sampler::now_ms;

/// Lookups that can run at the same time.
const WORKERS: usize = 4;
/// Lookups waiting for a worker. Anything beyond this is dropped and retried on a later refresh.
const QUEUE_DEPTH: usize = 256;
/// Per-query timeout. A slow upstream costs at most this per address.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
/// Longest name accepted from a PTR answer (RFC 1035 limit).
const MAX_NAME_LEN: usize = 253;

#[derive(Default)]
struct Upstreams {
    specs: Vec<String>,
    /// `None` when the configured list is empty or does not build; lookups then find nothing.
    resolver: Option<Arc<Resolver>>,
}

pub struct NameService {
    cache: Arc<Mutex<NameCache>>,
    upstreams: Arc<Mutex<Upstreams>>,
    queue: SyncSender<IpAddr>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panicked worker must not take the connection list down with it.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl NameService {
    /// Starts the worker threads. Lookups do nothing until [`set_upstreams`](Self::set_upstreams)
    /// has been called with a usable list.
    pub fn start() -> Arc<Self> {
        let (queue, rx) = mpsc::sync_channel::<IpAddr>(QUEUE_DEPTH);
        let rx = Arc::new(Mutex::new(rx));
        let service = Arc::new(NameService {
            cache: Arc::new(Mutex::new(NameCache::new())),
            upstreams: Arc::new(Mutex::new(Upstreams::default())),
            queue,
        });
        for _ in 0..WORKERS {
            let rx = Arc::clone(&rx);
            let cache = Arc::clone(&service.cache);
            let upstreams = Arc::clone(&service.upstreams);
            std::thread::spawn(move || worker(&rx, &cache, &upstreams));
        }
        service
    }

    /// Points lookups at the configured resolver. The resolver is rebuilt only when the list
    /// actually changes, so this is cheap to call on every refresh.
    pub fn set_upstreams(&self, specs: &[String]) {
        let mut up = lock(&self.upstreams);
        if up.specs.as_slice() == specs {
            return;
        }
        up.specs = specs.to_vec();
        up.resolver = if specs.is_empty() {
            None
        } else {
            resolver_from_specs(specs, LOOKUP_TIMEOUT)
                .ok()
                .map(Arc::new)
        };
    }

    /// Queues a lookup for each address that has no fresh answer. Addresses already queued are
    /// skipped, and a full queue drops the address until the next refresh asks again.
    pub fn enqueue(&self, ips: impl IntoIterator<Item = IpAddr>) {
        let now = now_ms();
        for ip in ips {
            let queued = {
                let mut cache = lock(&self.cache);
                cache.needs_lookup(ip, now) && cache.mark_queued(ip)
            };
            if queued && self.queue.try_send(ip).is_err() {
                lock(&self.cache).cancel(ip);
            }
        }
    }

    /// The last known name for `ip`, if any.
    pub fn name(&self, ip: IpAddr) -> Option<String> {
        lock(&self.cache).name(ip).map(str::to_owned)
    }
}

fn worker(
    rx: &Mutex<std::sync::mpsc::Receiver<IpAddr>>,
    cache: &Mutex<NameCache>,
    upstreams: &Mutex<Upstreams>,
) {
    loop {
        // The receiver lock is held only while waiting for the next address.
        let ip = match lock(rx).recv() {
            Ok(ip) => ip,
            Err(_) => return, // every sender is gone: the app is shutting down
        };
        let resolver = lock(upstreams).resolver.clone();
        let name = resolver
            .and_then(|r| r.reverse_lookup(ip).ok().flatten())
            .and_then(sanitize_name);
        lock(cache).complete(ip, name, now_ms());
    }
}

/// Keeps a PTR name only if it is a plausible host name: no trailing root dot, no control
/// characters, and within the length limit. Anything else is treated as "no name".
pub fn sanitize_name(raw: String) -> Option<String> {
    let name = raw.trim_end_matches('.');
    let plausible = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name.chars().all(|c| !c.is_control() && !c.is_whitespace());
    plausible.then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_root_dot_is_dropped() {
        assert_eq!(
            sanitize_name("host.example.net.".into()),
            Some("host.example.net".into())
        );
    }

    #[test]
    fn implausible_names_are_rejected() {
        assert_eq!(sanitize_name(String::new()), None);
        assert_eq!(sanitize_name(".".into()), None);
        assert_eq!(sanitize_name("bad\nname".into()), None);
        assert_eq!(sanitize_name("has space.example".into()), None);
        assert_eq!(sanitize_name("a".repeat(MAX_NAME_LEN + 1)), None);
    }

    #[test]
    fn an_empty_upstream_list_resolves_nothing() {
        let service = NameService::start();
        service.set_upstreams(&[]);
        service.enqueue([IpAddr::from([203, 0, 113, 9])]);
        assert_eq!(service.name(IpAddr::from([203, 0, 113, 9])), None);
    }
}
