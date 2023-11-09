use crate::platform::Platform;
use parking_lot::RwLock;
use std::sync::Arc;
use trace::Trace;
use tracing::instrument;
use trippy::tracing::{SocketImpl, Tracer, TracerChannel, TracerChannelConfig, TracerConfig};

pub mod flows;
pub mod trace;

/// Run the tracing backend.
///
/// Note that this implementation blocks the tracer on the `RwLock` and so any delays in the the TUI
/// will delay the next round of the started.
#[instrument(skip_all)]
pub fn run_backend(
    tracer_config: &TracerConfig,
    channel_config: &TracerChannelConfig,
    trace_data: Arc<RwLock<Trace>>,
) -> anyhow::Result<()> {
    let td = trace_data.clone();
    let channel = TracerChannel::<SocketImpl>::connect(channel_config).map_err(|err| {
        td.write().set_error(Some(err.to_string()));
        err
    })?;
    Platform::drop_privileges()?;
    let tracer = Tracer::new(tracer_config, move |round| {
        trace_data.write().update_from_round(round);
    });
    match tracer.trace(channel) {
        Ok(()) => {}
        Err(err) => {
            td.write().set_error(Some(err.to_string()));
        }
    };
    Ok(())
}
