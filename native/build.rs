// Apple dylibs get their install name rewritten after the build: Dart's
// bundler and Flutter's iOS/macOS framework packaging both run
// install_name_tool with the app's (possibly long) paths. Without spare header
// space that fails with "larger updated load commands do not fit", so reserve
// the maximum.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-headerpad_max_install_names");
    }
}
