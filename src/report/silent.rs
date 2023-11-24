use crate::TraceInfo;

/// Run a trace without generating any output.
pub fn report(info: &TraceInfo, report_cycles: usize) -> anyhow::Result<()> {
    super::wait_for_round(&info.data, report_cycles)?;
    Ok(())
}
