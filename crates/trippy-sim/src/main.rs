mod app;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    app::run().await?;
    Ok(())
}
