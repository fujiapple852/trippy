use crate::backend::trace::Trace;
use anyhow::anyhow;
use parking_lot::RwLock;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

pub mod csv;
pub mod dot;
pub mod flows;
pub mod json;
pub mod silent;
pub mod stream;
pub mod table;

/// Block until trace data for round `round` is available.
fn wait_for_round(trace_data: &Arc<RwLock<Trace>>, report_cycles: usize) -> anyhow::Result<Trace> {
    let mut trace = trace_data.read().clone();
    while trace.round(Trace::default_flow_id()).is_none()
        || trace.round(Trace::default_flow_id()) < Some(report_cycles - 1)
    {
        trace = trace_data.read().clone();
        if let Some(err) = trace.error() {
            return Err(anyhow!("error: {}", err));
        }
        sleep(Duration::from_millis(100));
    }
    Ok(trace)
}
