use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};

use chrono::Local;
use colored::Colorize;
use itertools::Itertools;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::InputSource;
use crate::errors::{RuleError, SanitizerMessage};

#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// Returns `Err` if `self == Error`, otherwise returns `Ok` and logs the message
    pub fn handle<T: Into<SanitizerMessage>>(self, logger: &impl Log, message: T) -> Result<(), T> {
        if self == LogLevel::Error {
            Err(message)
        } else {
            logger.log(self, message);
            Ok(())
        }
    }
}

/// A trait for logging messages
pub trait Log: Sync {
    fn log<T: Into<SanitizerMessage>>(&self, level: LogLevel, message: T);

    #[inline]
    fn trace<T: Into<SanitizerMessage>>(&self, message: T) {
        self.log(LogLevel::Trace, message);
    }

    #[inline]
    fn debug<T: Into<SanitizerMessage>>(&self, message: T) {
        self.log(LogLevel::Debug, message);
    }

    #[inline]
    fn info<T: Into<SanitizerMessage>>(&self, message: T) {
        self.log(LogLevel::Info, message);
    }

    #[inline]
    fn warn<T: Into<SanitizerMessage>>(&self, message: T) {
        self.log(LogLevel::Warn, message);
    }

    #[inline]
    fn error<T: Into<SanitizerMessage>>(&self, message: T) {
        self.log(LogLevel::Error, message);
    }

    fn subresource(&self, index: usize) -> Self;
}

#[derive(Clone)]
pub struct ChannelLogger {
    pub index: usize,
    pub subresource: usize,
    pub channel: Sender<LoggerMessage>,
}

impl Log for ChannelLogger {
    fn log<T: Into<SanitizerMessage>>(&self, level: LogLevel, message: T) {
        self.channel
            .send(LoggerMessage {
                source: self.index,
                subresource: self.subresource,
                level,
                message: message.into(),
            })
            .unwrap();
    }

    fn subresource(&self, index: usize) -> Self {
        Self {
            index: self.index,
            subresource: index,
            channel: self.channel.clone(),
        }
    }
}

impl Log for (usize, &Sender<LoggerMessage>) {
    fn log<T: Into<SanitizerMessage>>(&self, level: LogLevel, message: T) {
        self.1
            .send(LoggerMessage {
                source: self.0,
                subresource: 0,
                level,
                message: message.into(),
            })
            .unwrap();
    }

    fn subresource(&self, _: usize) -> Self {
        *self
    }
}

pub struct LoggerMessage {
    source: usize,
    subresource: usize,
    level: LogLevel,
    message: SanitizerMessage,
}

/// A logger that stores messages in a `Vec`, with interior mutability
#[derive(Default, Clone)]
pub struct VecLogger(Arc<Mutex<Vec<(LogLevel, SanitizerMessage)>>>);

impl VecLogger {
    pub fn new() -> Self {
        Self(Default::default())
    }
}

impl Log for VecLogger {
    fn log<T: Into<SanitizerMessage>>(&self, level: LogLevel, message: T) {
        self.0.lock().push((level, message.into()));
    }

    fn subresource(&self, _: usize) -> Self {
        self.clone()
    }
}

/// A logger that discards all messages
#[derive(Default)]
pub struct NullLogger;

impl Log for NullLogger {
    fn log<T: Into<SanitizerMessage>>(&self, _: LogLevel, _: T) {}

    fn subresource(&self, _: usize) -> Self {
        Self
    }
}

pub fn logging_thread(
    output: &Path,
    console_level: LogLevel,
    file_level: LogLevel,
    sources: &[InputSource],
    max_subresources: usize,
    channel: Receiver<LoggerMessage>,
) -> bool {
    use crate::errors::{SanitizationReport, SanitizerError};

    struct Subresource {
        source: Option<InputSource>,
        file: Option<File>,
        errors: Vec<RuleError>,
    }

    let mut sources = sources
        .iter()
        .enumerate()
        .map(|(i, x)| {
            HashMap::from([(
                0,
                Subresource {
                    source: Some(x.clone()),
                    file: File::create(output.join(format!("{i}.log"))).ok(),
                    errors: Vec::new(),
                },
            )])
        })
        .collect_vec();

    let width1 = (sources.len() as f64).log10().ceil() as usize;
    let width2 = (max_subresources as f64).log10().ceil() as usize;
    let mut has_errors = false;

    for msg in channel {
        let Some(source) = sources.get_mut(msg.source) else {
            continue;
        };

        let subresource = source
            .entry(msg.subresource)
            .or_insert_with(|| Subresource {
                source: None,
                file: File::create(output.join(format!("{}-{}.log", msg.source, msg.subresource)))
                    .ok(),
                errors: Vec::new(),
            });

        if let SanitizerMessage::CrawlingSubresource { url, .. } = &msg.message {
            subresource.source = Some(InputSource::Url(url.clone()));
        }

        if msg.level == LogLevel::Error {
            has_errors = true;
        }

        let error = msg.message.to_string();

        if msg.level >= console_level {
            println!(
                "[{}{}] {}: {}",
                format!("{:>width1$}", msg.source).bold().bright_blue(),
                if msg.subresource == 0 {
                    " ".repeat(width2 + 1)
                } else {
                    format!("/{:0>width2$}", msg.subresource.to_string().bold().blue())
                },
                match msg.level {
                    LogLevel::Trace => "TRACE".bright_black(),
                    LogLevel::Debug => "DEBUG".bright_blue(),
                    LogLevel::Info => " INFO".bright_green(),
                    LogLevel::Warn => " WARN".bright_yellow(),
                    LogLevel::Error => "ERROR".bright_red(),
                }
                .bold(),
                error,
            );
        }

        if msg.level >= file_level
            && let Some(ref mut file) = subresource.file
        {
            let now = Local::now().naive_local();
            let _ = writeln!(
                file,
                "({}) [{:>width1$}{}] {}: {}",
                now.format("%Y-%m-%d %H:%M:%S%.3f"),
                msg.source,
                if msg.subresource == 0 {
                    " ".repeat(width2 + 1)
                } else {
                    format!("/{:0>width2$}", msg.subresource)
                },
                match msg.level {
                    LogLevel::Trace => "TRACE",
                    LogLevel::Debug => "DEBUG",
                    LogLevel::Info => " INFO",
                    LogLevel::Warn => " WARN",
                    LogLevel::Error => "ERROR",
                },
                strip_ansi_escapes::strip_str(&error),
            );
        }

        // Collect sanitization action events if the message contains one
        if let SanitizerMessage::Error(SanitizerError::Rule(err)) = msg.message {
            subresource.errors.push(err);
        }
    }

    // Emit machine-readable JSON reports
    for (i, source) in sources.into_iter().enumerate() {
        for (j, subresource) in source {
            let file_name = if j == 0 {
                format!("{i}.json")
            } else {
                format!("{i}-{j}.json")
            };

            let input_source_str = match subresource.source {
                None => "<none>".to_owned(),
                Some(InputSource::File(p)) => p.to_string_lossy().to_string(),
                Some(InputSource::Url(u)) => u.to_string(),
            };

            let report = SanitizationReport {
                input: input_source_str,
                actions: subresource.errors,
            };

            if let Ok(file) = File::create(output.join(file_name)) {
                let _ = serde_json::to_writer_pretty(file, &report);
            }
        }
    }

    has_errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawl_session::CrawlSession;
    use crate::errors::RuleReplaceError;
    use crate::http_client::SanitizerHttpClient;
    use crate::policy::Policy;
    use parking_lot::Mutex;
    use std::assert_matches;
    use std::collections::HashMap;
    use std::fs;
    use std::sync::Arc;

    #[test]
    fn test_xml_bomb_rejection() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("temp_xml_bomb.html");
        fs::write(
            &file_path,
            b"<!DOCTYPE xmlbomb [ <!ENTITY lol 'lol'> ]><html></html>",
        )
        .unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let logger = ChannelLogger {
            index: 0,
            subresource: 0,
            channel: tx,
        };

        let policy = Arc::new(Policy::default());
        let url_map = Arc::new(Mutex::new(HashMap::new()));
        let client = Arc::new(
            SanitizerHttpClient::new(policy.clone(), logger.channel.clone(), url_map.clone())
                .unwrap(),
        );
        let runtime = tokio::runtime::Runtime::new().unwrap();

        let session = Arc::new(CrawlSession::new(
            client,
            policy,
            logger,
            runtime.handle().clone(),
            Arc::new(temp_dir.clone()),
            url_map,
        ));

        session.process_file(file_path.clone());

        // Clean up temp file
        let _ = fs::remove_file(file_path);

        // Retrieve the logged error
        let msg = rx.try_recv().expect("Expected a log message");
        let err_str = msg.message.to_string();
        assert!(err_str.contains("custom XML entity declaration detected"));
    }

    #[test]
    fn test_sanitization_report_generation() {
        use crate::errors::{RuleError, SanitizationReport};
        use std::path::PathBuf;

        let err = RuleError::Replace {
            inner: RuleReplaceError::DangerousScript {
                original: Some("evil_script()".to_owned()),
            },
            replacement: None,
            offset: 10..20,
        };
        // let event = err.to_event();
        // assert_eq!(event.rule, "allow_scripts");
        // assert_eq!(event.original, "evil_script()");
        // assert_eq!(event.offset, Some(10..20));

        let temp_dir = std::env::temp_dir();
        let (tx, rx) = std::sync::mpsc::channel();

        // Send a message on the channel
        tx.send(LoggerMessage {
            source: 0,
            subresource: 0,
            level: LogLevel::Error,
            message: err.into(),
        })
        .unwrap();
        drop(tx);

        let sources = vec![InputSource::File(PathBuf::from("test_input.html"))];
        let has_errors =
            logging_thread(&temp_dir, LogLevel::Error, LogLevel::Trace, &sources, 1, rx);
        assert!(has_errors);

        // Check if the report file was created
        let report_path = temp_dir.join("0.json");
        assert!(report_path.exists());

        // Read and parse report
        let content = std::fs::read_to_string(&report_path).unwrap();
        let report: SanitizationReport = serde_json::from_str(&content).unwrap();
        assert_eq!(report.input, "test_input.html");
        assert_eq!(report.actions.len(), 1);
        assert_matches!(
            report.actions[0],
            RuleError::Replace {
                inner: RuleReplaceError::DangerousScript { .. },
                ..
            }
        );

        // Cleanup
        let _ = std::fs::remove_file(report_path);
        let _ = std::fs::remove_file(temp_dir.join("0.log"));
    }
}
