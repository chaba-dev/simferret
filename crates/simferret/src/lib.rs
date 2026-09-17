pub mod agent;
pub mod assertions;
pub mod fixture;
pub mod guest;
pub mod protocol;
pub mod run;
// The guest process runtime changes root, drops credentials, creates device
// nodes, and signals the guest process table, so it is Linux-only. Other
// platforms compile against a placeholder with the same public surface.
#[cfg(target_os = "linux")]
pub mod runtime;
#[cfg(not(target_os = "linux"))]
#[path = "runtime_stub.rs"]
pub mod runtime;
pub mod scenario;
pub mod vm;
pub mod workload;
