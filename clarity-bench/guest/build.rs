//! `KERNEL_CASE=<id>` builds a guest that only contains that case's code.
fn main() {
    println!("cargo::rerun-if-env-changed=KERNEL_CASE");
    let fixed = match std::env::var("KERNEL_CASE") {
        Ok(id) => format!("Some({})", id.parse::<u32>().expect("KERNEL_CASE must be a case id")),
        Err(_) => "None".to_string(),
    };
    let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("fixed_case.rs");
    std::fs::write(out, format!("const FIXED_CASE: Option<u32> = {fixed};\n")).unwrap();
}
