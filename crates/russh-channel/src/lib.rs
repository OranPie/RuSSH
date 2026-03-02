//! SSH channel/session abstractions and forwarding models.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use russh_core::{RusshError, RusshErrorCategory};
use russh_transport::ClientSession;

static NEXT_CHANNEL_ID: AtomicU32 = AtomicU32::new(0);

/// Unique channel identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ChannelId(u32);

impl ChannelId {
    #[must_use]
    pub fn next() -> Self {
        Self(NEXT_CHANNEL_ID.fetch_add(1, Ordering::Relaxed))
    }

    #[must_use]
    pub fn value(self) -> u32 {
        self.0
    }
}

/// SSH channel kinds used by high-level APIs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelKind {
    Session,
    DirectTcpIp { host: String, port: u16 },
    ForwardedTcpIp { host: String, port: u16 },
    StreamLocal { path: String },
}

/// Basic channel handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Channel {
    pub id: ChannelId,
    pub kind: ChannelKind,
    pub open: bool,
}

impl Channel {
    #[must_use]
    pub fn open(kind: ChannelKind) -> Self {
        Self {
            id: ChannelId::next(),
            kind,
            open: true,
        }
    }

    pub fn close(&mut self) {
        self.open = false;
    }
}

/// TCP forwarding registration token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardHandle {
    pub bind_host: String,
    pub bind_port: u16,
    pub active: bool,
}

impl ForwardHandle {
    #[must_use]
    pub fn new(bind_host: impl Into<String>, bind_port: u16) -> Self {
        Self {
            bind_host: bind_host.into(),
            bind_port,
            active: true,
        }
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

/// Jump host chain model (ProxyJump style).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JumpChain {
    hops: Vec<String>,
}

impl JumpChain {
    pub fn new(hops: Vec<String>) -> Result<Self, RusshError> {
        if hops.is_empty() {
            return Err(RusshError::new(
                RusshErrorCategory::Config,
                "jump chain requires at least one hop",
            ));
        }

        Ok(Self { hops })
    }

    #[must_use]
    pub fn hops(&self) -> &[String] {
        &self.hops
    }
}

/// Lightweight multiplexing pool that reuses established client sessions by key.
#[derive(Debug, Default)]
pub struct ConnectionPool {
    entries: Arc<Mutex<HashMap<String, Arc<ClientSession>>>>,
}

impl ConnectionPool {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn insert(&self, key: impl Into<String>, session: ClientSession) -> Result<(), RusshError> {
        let mut guard = self.entries.lock().map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Channel,
                "connection pool lock poisoned during insert",
            )
        })?;
        guard.insert(key.into(), Arc::new(session));
        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<Option<Arc<ClientSession>>, RusshError> {
        let guard = self.entries.lock().map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Channel,
                "connection pool lock poisoned during get",
            )
        })?;
        Ok(guard.get(key).cloned())
    }

    pub fn len(&self) -> Result<usize, RusshError> {
        let guard = self.entries.lock().map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Channel,
                "connection pool lock poisoned during len",
            )
        })?;
        Ok(guard.len())
    }

    pub fn is_empty(&self) -> Result<bool, RusshError> {
        self.len().map(|count| count == 0)
    }
}

/// Typed channel-level events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelEvent {
    Opened { id: ChannelId, kind: ChannelKind },
    Closed { id: ChannelId },
    ForwardingEnabled { bind_host: String, bind_port: u16 },
    ForwardingDisabled { bind_host: String, bind_port: u16 },
}

#[cfg(test)]
mod tests {
    use russh_transport::ClientConfig;

    use super::{Channel, ChannelKind, ConnectionPool, JumpChain};

    #[test]
    fn channel_opens_with_unique_ids() {
        let first = Channel::open(ChannelKind::Session);
        let second = Channel::open(ChannelKind::Session);
        assert!(first.open);
        assert!(second.open);
        assert_ne!(first.id.value(), second.id.value());
    }

    #[test]
    fn jump_chain_requires_hops() {
        assert!(JumpChain::new(vec![]).is_err());
        assert!(JumpChain::new(vec!["jump.example".to_string()]).is_ok());
    }

    #[test]
    fn connection_pool_reuses_by_key() {
        let pool = ConnectionPool::new();
        let session = russh_transport::ClientSession::new(ClientConfig::secure_defaults("alice"));
        pool.insert("main", session).expect("insert should succeed");
        let found = pool.get("main").expect("get should succeed");
        assert!(found.is_some());
    }
}
