#[cfg(test)]
pub fn insta<F: FnOnce()>(name: &str, f: F) {
    let mut settings = insta::Settings::new();
    settings.set_snapshot_suffix(name.replace(' ', "_"));
    settings.set_snapshot_path("../tests/resources/snapshots");
    settings.set_omit_expression(true);
    settings.bind(f);
}

#[cfg(test)]
pub fn remove_whitespace(mut s: String) -> String {
    s.retain(|c| !c.is_whitespace());
    s
}
