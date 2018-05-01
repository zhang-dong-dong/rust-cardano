//! Tooling for providing logging and debug information
//! regarding operations
//! 

use std::{time, fmt, io, slice};
use std::io::{Write};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Level {
    Debug,
    Info,
    Warning,
    Error
}
impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Level::Debug    => { write!(f, "DEBUG") }
            &Level::Info     => { write!(f, "INFO ") }
            &Level::Warning  => { write!(f, "WARN ") }
            &Level::Error    => { write!(f, "ERROR") }
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Location {
    pub module_path: &'static str,
    pub file: &'static str,
    pub line: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Record {
    pub level: Level,
    pub location: Location,
    pub timestamp: time::SystemTime,
    pub message: String
}
impl Record {
    pub fn new<'a>(lvl: Level, loc: Location, args: fmt::Arguments<'a>) -> Self {
        Record {
            level: lvl,
            location: loc,
            timestamp: time::SystemTime::now(),
            message: format!("{}", args)
        }
    }
}

pub trait Logger {
    fn log(&mut self, record: Record);
}

#[macro_export]
macro_rules! log_enabled {
    ($lvl:expr) => ({
        let lvl = $lvl;
        (lvl != ::log::Level::Debug || cfg!(debug_assertions))
    })
}

#[macro_export]
macro_rules! record {
    ($logger:ident, $lvl:expr, $($arg:tt)+) => ({
        let loc : ::log::Location = ::log::Location {
            module_path: module_path!(),
            line: line!(),
            file: file!(),
        };
        let lvl = $lvl;
        if log_enabled!(lvl) {
            $logger.log(::log::Record::new(lvl, loc, format_args!($($arg)+)));
        }
    })
}

#[macro_export]
macro_rules! debug {
    ($logger:ident, $($arg:tt)+) => (
        if cfg!(debug_assertions) {
            record!($logger, ::log::Level::Debug, $($arg)*)
        }
    )
}

#[macro_export]
macro_rules! info {
    ($logger:ident, $($arg:tt)+) => ({
        record!($logger, ::log::Level::Info, $($arg)*)
    })
}

#[macro_export]
macro_rules! warn {
    ($logger:ident, $($arg:tt)+) => ({
        record!($logger, ::log::Level::Warning, $($arg)*)
    })
}

#[macro_export]
macro_rules! error {
    ($logger:ident, $($arg:tt)+) => ({
        record!($logger, ::log::Level::Error, $($arg)*)
    })
}

pub struct StderrLogger {
    handle: io::Stderr
}
impl Default for StderrLogger {
    fn default() -> Self { StderrLogger { handle: io::stderr() } }
}
impl Drop for StderrLogger {
    fn drop(&mut self) {
        match self.handle.flush() {
            Err(e) => panic!("failed to flush a logger: {:?}", e),
            Ok(()) => {}
        }
    }
}
impl Logger for StderrLogger {
    fn log(&mut self, record: Record) {
        match writeln!(&mut self.handle,
                       "[{}][{}:{}][{}]: {}",
                       record.level,
                       record.location.file,
                       record.location.line,
                       record.location.module_path,
                       record.message) {
            Err(e) => panic!("failed to log: {:?}", e),
            Ok(()) => {}
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq, Clone)]
pub struct MemmoryLogger(Vec<Record>);
impl MemmoryLogger {
    pub fn iter(&self) -> slice::Iter<Record> { self.0.iter() }
}
impl MemmoryLogger {
    pub fn new() -> Self {
        let mut ml = MemmoryLogger(vec![]);
        info!(ml
             , "starting logging with {}-{}'s module: {}"
             , env!("CARGO_PKG_NAME")
             , env!("CARGO_PKG_VERSION")
             , module_path!()
             );
        ml
    }
}
impl fmt::Display for MemmoryLogger {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for record in self.iter() {
            writeln!(f,
                "[{}][{}:{}][{}]: {}",
                record.level,
                record.location.file,
                record.location.line,
                record.location.module_path,
                record.message
            )?;
        }
        write!(f, "")
    }
}
impl Logger for MemmoryLogger {
    fn log(&mut self, record: Record) {
        self.0.push(record)
    }
}
