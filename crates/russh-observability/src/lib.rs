//! Observability primitives for typed events and metrics hooks.

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
