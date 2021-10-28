fn main() {
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rerun-if-changed=build.rs");
}
