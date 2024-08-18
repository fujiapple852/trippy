/// The sparkline [widget] is derived from from [Ratatui] which is made
/// available under the MIT license.
///
/// It has been modified to support custom empty bar styles.
///
/// This should be removed once the upstream widget is updated to support
/// custom empty bar styles.  See [this] issue in the upstream repository.
///
/// [Ratatui]: https://github.com/ratatui-org/ratatui
/// [widget]: https://github.com/ratatui-org/ratatui/blob/main/src/widgets/sparkline.rs
/// [this]: https://github.com/ratatui-org/ratatui/issues/1325
#[allow(dead_code)]
pub mod sparkline;
