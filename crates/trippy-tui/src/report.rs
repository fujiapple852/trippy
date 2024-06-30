use anyhow::anyhow;
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
fn wait_for_round(trace_data: &Tracer, report_cycles: usize) -> anyhow::Result<State> {
    let mut trace = trace_data.snapshot();
    while trace.round(State::default_flow_id()).is_none()
        || trace.round(State::default_flow_id()) < Some(report_cycles - 1)
    {
        trace = trace_data.snapshot();
        if let Some(err) = trace.error() {
            return Err(anyhow!("error: {}", err));
        }
    }
    Ok(trace)
}
