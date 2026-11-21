pub fn main() {
    println!("cargo:rerun-if-changed=locales.toml");
    println!("cargo:rerun-if-changed=themes");
}
