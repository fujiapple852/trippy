use crate::app::TraceInfo;
use std::thread::JoinHandle;

/// Run a trace and report all flows observed.
pub fn report(info: &TraceInfo, handle: JoinHandle<trippy_core::Result<()>>) -> anyhow::Result<()> {
    super::wait_for_round(&info.data, handle)?;
    let trace = info.data.snapshot();
    for (flow, flow_id) in trace.flows() {
        println!("flow {flow_id}: {flow}");
    }
    Ok(())
}
