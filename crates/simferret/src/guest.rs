use std::io;

#[cfg(target_os = "linux")]
use std::fs::{self, OpenOptions};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(target_os = "linux")]
pub fn init() -> io::Result<i32> {
    if std::process::id() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "guest init can run only as PID 1 in the SimFerret guest",
        ));
    }
    mount("devtmpfs", "/dev", "devtmpfs").map_err(|error| guest_error("mount /dev", error))?;
    mount("proc", "/proc", "proc").map_err(|error| guest_error("mount /proc", error))?;
    mount("sysfs", "/sys", "sysfs").map_err(|error| guest_error("mount /sys", error))?;
    bring_up_loopback().map_err(|error| guest_error("bring up loopback", error))?;

    let channel = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/ttyS1")
        .map_err(|error| guest_error("open guest output channel", error))?;
    configure_serial(&channel)?;
    let mut input = channel.try_clone()?;
    let mut output = channel;
    crate::protocol::write_line_frame(
        &mut output,
        &crate::protocol::EventFrame {
            protocol_version: crate::protocol::PROTOCOL_VERSION,
            event_id: 0,
            command_id: 0,
            event: crate::protocol::Event::AgentReady {},
            diagnostics: crate::protocol::DiagnosticFields::default(),
        },
    )?;
    let executable = std::env::current_exe()?;
    let status = crate::agent::run_serial(&mut input, &mut output, &executable)?;

    // SAFETY: reboot is called by PID 1 in the isolated guest after all fixture
    // processes have been reaped and all semantic output has been flushed.
    let result = unsafe { libc::reboot(libc::RB_POWER_OFF) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(status)
}

#[cfg(target_os = "linux")]
fn guest_error(operation: &str, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("guest init could not {operation}: {error}"),
    )
}

#[cfg(target_os = "linux")]
fn configure_serial(channel: &std::fs::File) -> io::Result<()> {
    let mut attributes = std::mem::MaybeUninit::uninit();
    // SAFETY: attributes points to writable storage and channel owns a tty fd.
    if unsafe { libc::tcgetattr(channel.as_raw_fd(), attributes.as_mut_ptr()) } < 0 {
        return Err(guest_error(
            "read guest channel settings",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: tcgetattr initialized attributes after succeeding above.
    let mut attributes = unsafe { attributes.assume_init() };
    // SAFETY: attributes is initialized and exclusively borrowed.
    unsafe { libc::cfmakeraw(&mut attributes) };
    // SAFETY: attributes is initialized and channel owns a tty fd.
    if unsafe { libc::tcsetattr(channel.as_raw_fd(), libc::TCSANOW, &attributes) } < 0 {
        return Err(guest_error(
            "configure guest channel",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn init() -> io::Result<i32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "guest init supports Linux only",
    ))
}

#[cfg(target_os = "linux")]
fn mount(source: &str, target: &str, filesystem: &str) -> io::Result<()> {
    fs::create_dir_all(target)?;
    let source = std::ffi::CString::new(source).unwrap();
    let target = std::ffi::CString::new(target).unwrap();
    let filesystem = std::ffi::CString::new(filesystem).unwrap();
    // SAFETY: all pointers refer to live NUL-terminated strings, flags are zero,
    // and the data pointer is unused by these virtual filesystems.
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            filesystem.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn bring_up_loopback() -> io::Result<()> {
    #[repr(C)]
    struct InterfaceRequest {
        name: [libc::c_char; libc::IFNAMSIZ],
        data: [u8; 24],
    }

    let mut request = InterfaceRequest {
        name: [0; libc::IFNAMSIZ],
        data: [0; 24],
    };
    request.name[0] = b'l' as libc::c_char;
    request.name[1] = b'o' as libc::c_char;
    request.data[..std::mem::size_of::<libc::c_short>()]
        .copy_from_slice(&(libc::IFF_UP as libc::c_short).to_ne_bytes());

    // SAFETY: socket returns an owned descriptor and ioctl receives the Linux
    // ifreq layout for x86-64, the only supported Phase 2 guest architecture.
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if socket < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: request is initialized, writable, and has the x86-64 ifreq size.
    let result = unsafe { libc::ioctl(socket, libc::SIOCSIFFLAGS as _, &request) };
    // SAFETY: socket is an owned descriptor returned above and is closed once.
    unsafe { libc::close(socket) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn guest_init_rejects_non_pid_one_before_privileged_operations() {
        let error = super::init().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("PID 1"));
    }
}
