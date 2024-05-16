use crate::TraceInfo;

/// Run a trace and report all flows observed.
pub fn report(info: &TraceInfo, report_cycles: usize) -> anyhow::Result<()> {
    super::wait_for_round(&info.data, report_cycles)?;
    let trace = info.data.read().clone();
    for (flow, flow_id) in trace.flows() {
        println!("flow {flow_id}: {flow}");
    }
    Ok(())
}
