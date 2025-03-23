use crate::app::TraceInfo;
use tracing::instrument;

/// Run a trace without generating any output.
#[instrument(skip_all, level = "trace")]
pub fn report(info: &TraceInfo, report_cycles: usize) -> anyhow::Result<()> {
    super::wait_for_round(&info.data, report_cycles)?;
    Ok(())
}
