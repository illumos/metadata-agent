
use atty::Stream;
use slog::Drain;
use std::sync::Mutex;

pub use slog::{info, warn, error, debug, trace, o, Logger};
pub use anyhow::{bail, Result, Context};

/**
 * Initialise a logger which writes to stdout, and which does the right thing on
 * both an interactive terminal and when stdout is not a tty.
 */
pub fn init_log() -> Logger {
    let dec = slog_term::TermDecorator::new().stdout().build();
    if atty::is(Stream::Stdout) {
        let dr = Mutex::new(slog_term::CompactFormat::new(dec)
            .build()).fuse();
        slog::Logger::root(dr, o!())
    } else {
        let dr = Mutex::new(slog_term::FullFormat::new(dec)
            .use_original_order()
            .build()).fuse();
        slog::Logger::root(dr, o!())
    }
}
