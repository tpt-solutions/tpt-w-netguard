// SPDX-License-Identifier: MIT OR Apache-2.0
fn main() {
    // Release builds embed the elevation manifest (see app.manifest) so the app asks for
    // administrator rights at launch. Debug and test builds skip it so `cargo test` and
    // `tauri dev` run unelevated; those builds start in monitor-only mode unless the terminal
    // was started as administrator.
    let release = std::env::var("PROFILE").as_deref() == Ok("release");
    let mut windows = tauri_build::WindowsAttributes::new();
    if release {
        windows = windows.app_manifest(include_str!("app.manifest"));
    }
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("tauri-build failed");
}
