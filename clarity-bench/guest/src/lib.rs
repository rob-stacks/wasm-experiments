//! Wasm entry points. The host writes a case's input into memory obtained from
//! `alloc`, then calls `run`, which loops inside the guest so per-call host/guest
//! transition costs don't distort the cheap functions.

#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

// `FIXED_CASE`: set from the KERNEL_CASE env var at build time (see build.rs).
include!(concat!(env!("OUT_DIR"), "/fixed_case.rs"));

#[no_mangle]
pub extern "C" fn run(case: u32, ptr: *const u8, len: usize, iters: u32) -> u64 {
    let input = unsafe { std::slice::from_raw_parts(ptr, len) };
    // With a fixed case the match in `kernels::run` folds to one arm, so the module
    // contains only that built-in's code (used for code-size measurements).
    kernels::run(FIXED_CASE.unwrap_or(case), input, iters)
}

/// No entropy inside the guest; any attempt to use it fails.
fn no_entropy(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
getrandom::register_custom_getrandom!(no_entropy);
