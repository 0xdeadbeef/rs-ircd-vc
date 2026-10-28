//! Process daemonisation.
//!
//! On Unix the classic double-fork is used so the daemon cannot reacquire a
//! controlling terminal. It must run before the Tokio runtime is created;
//! forking a multithreaded process is undefined behaviour.

use crate::config::DaemonSection;
use crate::error::Result;

/// Detach the process according to `config`.
///
/// # Errors
///
/// Returns [`crate::error::Error::Io`] if forking, redirecting standard
/// streams, changing directory or writing the PID file fails.
pub fn daemonize(config: &DaemonSection) -> Result<()> {
    #[cfg(unix)]
    {
        if !config.enabled {
            return Ok(());
        }
        // MARK: safety: high: SAF-FORK-001: runs before any thread or runtime exists.
        // Safety: called from `main` before any threads (including the Tokio
        // runtime) exist, so fork cannot duplicate a locked mutex or an
        // in-flight allocation in another thread.
        unsafe {
            match libc::fork() {
                -1 => return Err(std::io::Error::last_os_error().into()),
                0 => {}
                _ => libc::_exit(0),
            }
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error().into());
            }
            match libc::fork() {
                -1 => return Err(std::io::Error::last_os_error().into()),
                0 => {}
                _ => libc::_exit(0),
            }
        }
        redirect_standard_streams()?;
        apply_working_directory(config)?;
        write_pid_file(config)?;
        Ok(())
    }

    #[cfg(windows)]
    {
        if !config.enabled {
            return Ok(());
        }
        // Windows has no fork: detach from the console and let the caller's
        // service wrapper keep the process alive.
        unsafe {
            windows_sys::Win32::System::Console::FreeConsole();
        }
        apply_working_directory(config)?;
        write_pid_file(config)?;
        return Ok(());
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = config;
        Ok(())
    }
}

fn apply_working_directory(config: &DaemonSection) -> Result<()> {
    if let Some(directory) = &config.working_directory {
        std::env::set_current_dir(directory)?;
    }
    Ok(())
}

fn write_pid_file(config: &DaemonSection) -> Result<()> {
    if let Some(path) = &config.pid_file {
        std::fs::write(path, format!("{}\n", std::process::id()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn redirect_standard_streams() -> Result<()> {
    use std::os::fd::AsRawFd;

    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // Safety: `null` is a valid open descriptor for the whole call.
        if unsafe { libc::dup2(null.as_raw_fd(), target) } == -1 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_file_is_written() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("ircd.pid");
        let config = DaemonSection {
            enabled: false,
            pid_file: Some(path.to_string_lossy().into_owned()),
            working_directory: None,
        };
        write_pid_file(&config).expect("pid file");
        let contents = std::fs::read_to_string(path).expect("read pid");
        assert_eq!(contents.trim(), std::process::id().to_string());
    }

    #[test]
    fn disabled_daemon_does_not_fork() {
        daemonize(&DaemonSection::default()).expect("no-op");
    }
}
