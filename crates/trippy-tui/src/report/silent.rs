use crate::app::TraceInfo;
use std::thread::JoinHandle;

/// Run a trace without generating any output.
pub fn report(info: &TraceInfo, handle: JoinHandle<trippy_core::Result<()>>) -> anyhow::Result<()> {
    super::wait_for_round(&info.data, handle)?;
    Ok(())
}
