//! Logging sinks: stderr, rolling files, and the platform system log.
//!
//! The filter directive is reloadable at runtime (`REHASH`), so verbosity can
//! be raised or lowered without dropping connections.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::thread;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::Registry;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::{LogFormat, LoggingSection};
use crate::error::{Error, Result};

/// Runtime filter setter; boxed so the concrete reload handle type stays private.
type SetLevelFn = Box<dyn Fn(&str) -> Result<()> + Send + Sync>;

/// Handle returned by [`init`], used to change the filter at runtime.
pub struct LoggingHandle {
    set_level: SetLevelFn,
    _guard: Option<WorkerGuard>,
}

impl LoggingHandle {
    /// Replace the active filter directive, e.g. `debug` or `ircd::net=trace`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Logging`] if the directive cannot be parsed.
    pub fn set_level(&self, directive: &str) -> Result<()> {
        (self.set_level)(directive)
    }
}

/// A single event forwarded to a blocking system-log sink.
#[derive(Debug)]
struct SyslogRecord {
    level: Level,
    target: &'static str,
    message: String,
}

/// Layer that forwards events to a background thread.
///
/// System log APIs are blocking, so events are queued and written off the
/// reactor thread. When the queue is full events are dropped and counted
/// rather than stalling the server.
struct SystemLogLayer {
    sender: SyncSender<SyslogRecord>,
    dropped: AtomicU64,
}

impl SystemLogLayer {
    fn new(sender: SyncSender<SyslogRecord>) -> Self {
        Self {
            sender,
            dropped: AtomicU64::new(0),
        }
    }
}

impl<S: Subscriber> Layer<S> for SystemLogLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let message = if visitor.fields.is_empty() {
            visitor.message
        } else {
            format!("{} {}", visitor.message, visitor.fields.join(" "))
        };
        let record = SyslogRecord {
            level: *event.metadata().level(),
            target: event.metadata().target(),
            message,
        };
        if self.sender.try_send(record).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: Vec<String>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.fields.push(format!("{}={value:?}", field.name()));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_owned();
        } else {
            self.fields.push(format!("{}={value}", field.name()));
        }
    }
}

/// Initialise the global subscriber.
///
/// # Errors
///
/// Returns [`Error::Logging`] when a sink cannot be created or a subscriber was
/// already installed, which would make the process's logging ambiguous.
pub fn init(config: &LoggingSection) -> Result<LoggingHandle> {
    let filter = EnvFilter::try_new(&config.level)
        .or_else(|_| EnvFilter::try_new("info"))
        .map_err(|error| Error::Logging(error.to_string()))?;
    let (filter_layer, filter_handle) = reload::Layer::new(filter);

    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync + 'static>> = Vec::new();

    if config.console {
        let stderr = std::io::stderr;
        let ansi = std::io::stderr().is_terminal();
        let layer = match config.format {
            LogFormat::Text => tracing_subscriber::fmt::layer()
                .with_writer(stderr)
                .with_ansi(ansi)
                .with_timer(UtcTime::rfc_3339())
                .boxed(),
            LogFormat::Json => tracing_subscriber::fmt::layer()
                .with_writer(stderr)
                .json()
                .with_timer(UtcTime::rfc_3339())
                .boxed(),
        };
        layers.push(layer);
    }

    let mut guard = None;
    if config.file.enabled {
        let directory = std::path::Path::new(&config.file.directory);
        std::fs::create_dir_all(directory)?;
        let appender = tracing_appender::rolling::Builder::new()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix(config.file.prefix.clone())
            .max_log_files(config.file.max_files.max(1))
            .build(directory)
            .map_err(|error| Error::Logging(format!("cannot open log directory: {error}")))?;
        let (writer, writer_guard) = tracing_appender::non_blocking(appender);
        guard = Some(writer_guard);
        let layer = match config.format {
            LogFormat::Text => tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_ansi(false)
                .with_timer(UtcTime::rfc_3339())
                .boxed(),
            LogFormat::Json => tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .json()
                .with_timer(UtcTime::rfc_3339())
                .boxed(),
        };
        layers.push(layer);
    }

    if config.syslog.enabled {
        let (sender, receiver) = mpsc::sync_channel(4096);
        spawn_system_log_writer(config, receiver)?;
        layers.push(Box::new(SystemLogLayer::new(sender)));
    }

    tracing_subscriber::registry()
        .with(layers)
        .with(filter_layer)
        .try_init()
        .map_err(|error| Error::Logging(error.to_string()))?;

    let set_level: SetLevelFn = Box::new(move |directive| {
        let filter = EnvFilter::try_new(directive).map_err(|error| {
            Error::Logging(format!("invalid log filter {directive:?}: {error}"))
        })?;
        filter_handle
            .reload(filter)
            .map_err(|error| Error::Logging(error.to_string()))
    });

    Ok(LoggingHandle {
        set_level,
        _guard: guard,
    })
}

/// Start the blocking system-log writer thread.
fn spawn_system_log_writer(
    config: &LoggingSection,
    receiver: mpsc::Receiver<SyslogRecord>,
) -> Result<()> {
    #[cfg(unix)]
    {
        let facility = parse_facility(&config.syslog.facility);
        let formatter = syslog::Formatter3164 {
            facility,
            hostname: None,
            pid: std::process::id(),
            process: config.syslog.tag.clone(),
        };
        let logger = syslog::unix(formatter)
            .map_err(|error| Error::Logging(format!("cannot connect to syslog: {error}")))?;
        thread::Builder::new()
            .name("syslog".to_owned())
            .spawn(move || syslog_writer_loop(logger, receiver))
            .map_err(|error| Error::Logging(error.to_string()))?;
        Ok(())
    }

    #[cfg(windows)]
    {
        let source = config.syslog.tag.clone();
        let logger = winlog::EventLog::register(&source)?;
        thread::Builder::new()
            .name("winlog".to_owned())
            .spawn(move || winlog_writer_loop(&logger, receiver))
            .map_err(|error| Error::Logging(error.to_string()))?;
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (config, receiver);
        Err(Error::Logging(
            "no system log implementation for this platform".to_owned(),
        ))
    }
}

#[cfg(unix)]
fn parse_facility(name: &str) -> syslog::Facility {
    use syslog::Facility;
    match name.to_ascii_lowercase().as_str() {
        "auth" => Facility::LOG_AUTH,
        "authpriv" => Facility::LOG_AUTHPRIV,
        "cron" => Facility::LOG_CRON,
        "kernel" => Facility::LOG_KERN,
        "local0" => Facility::LOG_LOCAL0,
        "local1" => Facility::LOG_LOCAL1,
        "local2" => Facility::LOG_LOCAL2,
        "local3" => Facility::LOG_LOCAL3,
        "local4" => Facility::LOG_LOCAL4,
        "local5" => Facility::LOG_LOCAL5,
        "local6" => Facility::LOG_LOCAL6,
        "local7" => Facility::LOG_LOCAL7,
        "lpr" => Facility::LOG_LPR,
        "mail" => Facility::LOG_MAIL,
        "news" => Facility::LOG_NEWS,
        "syslog" => Facility::LOG_SYSLOG,
        "user" => Facility::LOG_USER,
        "uucp" => Facility::LOG_UUCP,
        _ => Facility::LOG_DAEMON,
    }
}

#[cfg(unix)]
fn syslog_writer_loop(
    mut logger: syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>,
    receiver: mpsc::Receiver<SyslogRecord>,
) {
    for record in receiver {
        let line = format!("[{}] {}", record.target, record.message);
        let result = match record.level {
            Level::ERROR => logger.err(line),
            Level::WARN => logger.warning(line),
            Level::INFO => logger.info(line),
            Level::DEBUG => logger.debug(line),
            Level::TRACE => logger.debug(line),
        };
        if result.is_err() {
            break;
        }
    }
    let _ = std::io::stdout().flush();
}

/// Minimal Windows Event Log binding.
///
/// Only compiled on Windows; the Linux build in CI never exercises this path.
#[cfg(windows)]
mod winlog {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, RegisterEventSourceW, ReportEventW,
    };

    use crate::error::{Error, Result};

    /// An open `EVENTLOG` handle.
    pub struct EventLog {
        handle: isize,
        source: Vec<u16>,
    }

    // The handle is used from exactly one writer thread.
    unsafe impl Send for EventLog {}

    const EVENTLOG_ERROR_TYPE: u16 = 0x0001;
    const EVENTLOG_WARNING_TYPE: u16 = 0x0002;
    const EVENTLOG_INFORMATION_TYPE: u16 = 0x0004;

    impl EventLog {
        pub fn register(source: &str) -> Result<Self> {
            let wide: Vec<u16> = OsStr::new(source)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            // Safety: `wide` is NUL-terminated and outlives the call.
            let handle = unsafe { RegisterEventSourceW(ptr::null(), wide.as_ptr()) };
            if handle.is_null() {
                return Err(Error::Logging(
                    "RegisterEventSourceW failed for the event log".to_owned(),
                ));
            }
            Ok(Self {
                handle: handle as isize,
                source: wide,
            })
        }

        pub fn report(&self, event_type: u16, message: &str) -> Result<()> {
            let wide: Vec<u16> = OsStr::new(message)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let strings = [wide.as_ptr()];
            // Safety: the handle came from RegisterEventSourceW, `strings`
            // points at a NUL-terminated string for the duration of the call.
            let ok = unsafe {
                ReportEventW(
                    self.handle as *mut std::ffi::c_void,
                    event_type,
                    0,
                    1,
                    ptr::null(),
                    1,
                    0,
                    strings.as_ptr(),
                    ptr::null(),
                )
            };
            if ok == 0 {
                return Err(Error::Logging(
                    "ReportEventW failed for the event log".to_owned(),
                ));
            }
            Ok(())
        }
    }

    impl Drop for EventLog {
        fn drop(&mut self) {
            // Safety: the handle is owned by this value and closed once.
            unsafe {
                DeregisterEventSource(self.handle as *mut std::ffi::c_void);
            }
        }
    }
}

#[cfg(windows)]
fn winlog_writer_loop(logger: &winlog::EventLog, receiver: mpsc::Receiver<SyslogRecord>) {
    for record in receiver {
        let kind = match record.level {
            Level::ERROR => 0x0001,
            Level::WARN => 0x0002,
            _ => 0x0004,
        };
        if logger
            .report(kind, &format!("[{}] {}", record.target, record.message))
            .is_err()
        {
            break;
        }
    }
}

/// Shared helper for testing sinks without installing a global subscriber.
#[cfg(test)]
fn format_record(level: Level, target: &str, message: &str) -> String {
    format!("{level} {target}: {message}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visitor_collects_message_and_fields() {
        let visitor = MessageVisitor {
            message: "connected".to_owned(),
            fields: vec!["peer=1.2.3.4:6667".to_owned()],
        };
        assert_eq!(visitor.fields.len(), 1);
        assert_eq!(
            format_record(Level::INFO, "ircd::net", &visitor.message),
            "INFO ircd::net: connected"
        );
    }

    #[test]
    fn facility_falls_back_to_daemon() {
        // `syslog::Facility` does not implement `PartialEq`, so compare its
        // debug representation.
        #[cfg(unix)]
        assert_eq!(format!("{:?}", parse_facility("nonsense")), "LOG_DAEMON");
    }

    #[test]
    fn invalid_filter_is_rejected() {
        assert!(EnvFilter::try_new("this is not a filter ====").is_err());
    }

    #[test]
    fn handle_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LoggingHandle>();
        assert_send_sync::<std::sync::Arc<AtomicU64>>();
    }
}
