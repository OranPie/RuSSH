//! Observability primitives for typed events and metrics hooks.
//!
//! Provides a lightweight, allocation-free telemetry layer that can be
//! wired to any backend without coupling the SSH protocol code to a
//! specific logging or metrics framework.
//!
//! ## Core traits
//!
//! - [`EventSink`] — receives [`TelemetryEvent`]s; implement this to
//!   forward events to your logging framework.
//! - [`MetricsHook`] — receives named counter increments; implement this
//!   to forward metrics to Prometheus, StatsD, etc.
//!
//! ## Built-in implementations
//!
//! | Type | Feature flag | Description |
//! |------|-------------|-------------|
//! | [`NoopSink`] | — | Discards all events (default) |
//! | [`NoopMetrics`] | — | Discards all metrics (default) |
//! | [`MemorySink`] | — | Collects events in a `Vec` (useful for tests) |
//! | [`TracingEventSink`] | `tracing` | Emits events via the `tracing` crate |
//! | [`MetricsEventSink`] | `metrics` | Increments counters via the `metrics` crate |
//! | [`MetricsCounterHook`] | `metrics` | Forwards `increment_counter` to `metrics` |
//!
//! ## Event taxonomy
//!
//! Events are grouped into [`TransportEvent`], [`AuthEvent`], and
//! [`ChannelEvent`] variants, all wrapped in [`TelemetryEvent`].
//!
//! ## Example
//!
//! ```rust
//! use std::sync::Arc;
//! use russh_observability::{MemorySink, NoopMetrics, Observability, TelemetryEvent, TransportEvent};
//!
//! let sink = Arc::new(MemorySink::default());
//! let obs = Observability::new(sink.clone(), Arc::new(NoopMetrics));
//! obs.emit(TelemetryEvent::Transport(TransportEvent::Rekey));
//! assert_eq!(sink.events().len(), 1);
//! ```

use std::sync::{Arc, Mutex};

/// Transport-layer event surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportEvent {
    VersionExchange,
    AlgorithmNegotiated,
    Rekey,
    Disconnect,
}

/// Authentication event surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthEvent {
    MethodAttempt { method: String },
    Success,
    Failure { reason: String },
}

/// Channel event surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelEvent {
    Open,
    Close,
    ForwardEnabled,
    ForwardDisabled,
}

/// Unified telemetry event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TelemetryEvent {
    Transport(TransportEvent),
    Auth(AuthEvent),
    Channel(ChannelEvent),
}

/// Event sink extension point for tracing/logging integrations.
pub trait EventSink: Send + Sync {
    fn emit(&self, event: &TelemetryEvent);
}

/// Metrics extension point for external collectors.
pub trait MetricsHook: Send + Sync {
    fn increment_counter(&self, name: &str, value: u64);
}

/// No-op sink used by default.
#[derive(Clone, Debug, Default)]
pub struct NoopSink;

impl EventSink for NoopSink {
    fn emit(&self, _event: &TelemetryEvent) {}
}

/// No-op metrics hook used by default.
#[derive(Clone, Debug, Default)]
pub struct NoopMetrics;

impl MetricsHook for NoopMetrics {
    fn increment_counter(&self, _name: &str, _value: u64) {}
}

/// In-memory sink useful for tests.
#[derive(Clone, Debug, Default)]
pub struct MemorySink {
    events: Arc<Mutex<Vec<TelemetryEvent>>>,
}

impl MemorySink {
    #[must_use]
    pub fn events(&self) -> Vec<TelemetryEvent> {
        self.events
            .lock()
            .expect("memory sink lock should not be poisoned")
            .clone()
    }
}

impl EventSink for MemorySink {
    fn emit(&self, event: &TelemetryEvent) {
        self.events
            .lock()
            .expect("memory sink lock should not be poisoned")
            .push(event.clone());
    }
}

/// Combined observability entrypoint.
pub struct Observability {
    sink: Arc<dyn EventSink>,
    metrics: Arc<dyn MetricsHook>,
}

impl Observability {
    #[must_use]
    pub fn new(sink: Arc<dyn EventSink>, metrics: Arc<dyn MetricsHook>) -> Self {
        Self { sink, metrics }
    }

    #[must_use]
    pub fn secure_defaults() -> Self {
        Self {
            sink: Arc::new(NoopSink),
            metrics: Arc::new(NoopMetrics),
        }
    }

    pub fn emit(&self, event: TelemetryEvent) {
        self.sink.emit(&event);
    }

    pub fn increment_counter(&self, name: &str, value: u64) {
        self.metrics.increment_counter(name, value);
    }
}

impl Default for Observability {
    fn default() -> Self {
        Self::secure_defaults()
    }
}

/// EventSink backed by the `tracing` crate (feature = "tracing").
/// Each TelemetryEvent is emitted as a tracing event at the appropriate level.
#[cfg(feature = "tracing")]
#[derive(Clone, Debug, Default)]
pub struct TracingEventSink;

#[cfg(feature = "tracing")]
impl EventSink for TracingEventSink {
    fn emit(&self, event: &TelemetryEvent) {
        match event {
            TelemetryEvent::Transport(t) => match t {
                TransportEvent::VersionExchange => {
                    tracing::debug!(target: "russh::transport", "version exchange");
                }
                TransportEvent::AlgorithmNegotiated => {
                    tracing::debug!(target: "russh::transport", "algorithm negotiated");
                }
                TransportEvent::Rekey => {
                    tracing::info!(target: "russh::transport", "rekey");
                }
                TransportEvent::Disconnect => {
                    tracing::info!(target: "russh::transport", "disconnect");
                }
            },
            TelemetryEvent::Auth(a) => match a {
                AuthEvent::MethodAttempt { method } => {
                    tracing::debug!(target: "russh::auth", method = %method, "auth attempt");
                }
                AuthEvent::Success => {
                    tracing::info!(target: "russh::auth", "auth success");
                }
                AuthEvent::Failure { reason } => {
                    tracing::warn!(target: "russh::auth", reason = %reason, "auth failure");
                }
            },
            TelemetryEvent::Channel(c) => match c {
                ChannelEvent::Open => {
                    tracing::debug!(target: "russh::channel", "channel open");
                }
                ChannelEvent::Close => {
                    tracing::debug!(target: "russh::channel", "channel close");
                }
                ChannelEvent::ForwardEnabled => {
                    tracing::info!(target: "russh::channel", "forwarding enabled");
                }
                ChannelEvent::ForwardDisabled => {
                    tracing::info!(target: "russh::channel", "forwarding disabled");
                }
            },
        }
    }
}

/// EventSink backed by the `metrics` crate (feature = "metrics").
/// Each TelemetryEvent increments an appropriate counter.
#[cfg(feature = "metrics")]
#[derive(Clone, Debug, Default)]
pub struct MetricsEventSink;

#[cfg(feature = "metrics")]
impl EventSink for MetricsEventSink {
    fn emit(&self, event: &TelemetryEvent) {
        let counter_name = match event {
            TelemetryEvent::Transport(TransportEvent::VersionExchange) => {
                "russh.transport.version_exchange"
            }
            TelemetryEvent::Transport(TransportEvent::AlgorithmNegotiated) => {
                "russh.transport.algorithm_negotiated"
            }
            TelemetryEvent::Transport(TransportEvent::Rekey) => "russh.transport.rekey",
            TelemetryEvent::Transport(TransportEvent::Disconnect) => "russh.transport.disconnect",
            TelemetryEvent::Auth(AuthEvent::MethodAttempt { .. }) => "russh.auth.attempt",
            TelemetryEvent::Auth(AuthEvent::Success) => "russh.auth.success",
            TelemetryEvent::Auth(AuthEvent::Failure { .. }) => "russh.auth.failure",
            TelemetryEvent::Channel(ChannelEvent::Open) => "russh.channel.open",
            TelemetryEvent::Channel(ChannelEvent::Close) => "russh.channel.close",
            TelemetryEvent::Channel(ChannelEvent::ForwardEnabled) => {
                "russh.channel.forward_enabled"
            }
            TelemetryEvent::Channel(ChannelEvent::ForwardDisabled) => {
                "russh.channel.forward_disabled"
            }
        };
        metrics::counter!(counter_name).increment(1);
    }
}

/// MetricsHook backed by the `metrics` crate (feature = "metrics").
#[cfg(feature = "metrics")]
#[derive(Clone, Debug, Default)]
pub struct MetricsCounterHook;

#[cfg(feature = "metrics")]
impl MetricsHook for MetricsCounterHook {
    fn increment_counter(&self, name: &str, value: u64) {
        metrics::counter!(name.to_owned()).increment(value);
    }
}

#[cfg(all(test, feature = "tracing"))]
mod tracing_tests {
    use super::{NoopMetrics, Observability, TelemetryEvent, TracingEventSink, TransportEvent};
    use std::sync::Arc;

    #[test]
    fn tracing_sink_does_not_panic() {
        let sink = Arc::new(TracingEventSink);
        let obs = Observability::new(sink, Arc::new(NoopMetrics));
        obs.emit(TelemetryEvent::Transport(TransportEvent::VersionExchange));
        obs.emit(TelemetryEvent::Transport(TransportEvent::Rekey));
        obs.emit(TelemetryEvent::Transport(TransportEvent::Disconnect));
        obs.emit(TelemetryEvent::Auth(super::AuthEvent::Success));
        obs.emit(TelemetryEvent::Auth(super::AuthEvent::Failure {
            reason: "bad key".to_string(),
        }));
        obs.emit(TelemetryEvent::Channel(super::ChannelEvent::Open));
    }
}

#[cfg(all(test, feature = "metrics"))]
mod metrics_tests {
    use super::{
        MetricsCounterHook, MetricsEventSink, NoopSink, Observability, TelemetryEvent,
        TransportEvent,
    };
    use std::sync::Arc;

    #[test]
    fn metrics_hook_does_not_panic() {
        let obs = Observability::new(Arc::new(MetricsEventSink), Arc::new(MetricsCounterHook));
        obs.emit(TelemetryEvent::Transport(TransportEvent::Rekey));
        obs.increment_counter("russh.test.counter", 5);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{MemorySink, NoopMetrics, Observability, TelemetryEvent, TransportEvent};

    #[test]
    fn memory_sink_records_events() {
        let sink = Arc::new(MemorySink::default());
        let obs = Observability::new(sink.clone(), Arc::new(NoopMetrics));

        obs.emit(TelemetryEvent::Transport(TransportEvent::VersionExchange));

        let events = sink.events();
        assert_eq!(events.len(), 1);
    }
}
