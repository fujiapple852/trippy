use anyhow::anyhow;
use std::thread::JoinHandle;
use trippy_core::State;
use trippy_core::Tracer;

pub mod csv;
pub mod dot;
pub mod flows;
pub mod json;
pub mod silent;
pub mod stream;
pub mod table;
mod types;

/// Block until trace data for round `round` is available.
fn wait_for_round(
    trace_data: &Tracer,
    handle: JoinHandle<trippy_core::Result<()>>,
) -> anyhow::Result<State> {
    handle.join().expect("failed to join thread")?;
    let trace = trace_data.snapshot();
    if let Some(err) = trace.error() {
        return Err(anyhow!("error: {}", err));
    }
    Ok(trace)
}
