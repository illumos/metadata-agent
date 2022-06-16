/*
 * Copyright 2020 Oxide Computer Company
 */

use crate::common::*;
use std::fs::{DirBuilder, File};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::io::{ErrorKind, BufReader, BufRead, copy as IOCopy, Read, Write};
use anyhow::{Result};

pub fn ensure_dir(log: &Logger, path: &str) -> Result<()> {
    if !exists_dir(path)? {
        info!(log, "mkdir {}", path);
        DirBuilder::new()
            .mode(0o700)
            .create(path)?;
    }
    Ok(())
}

pub fn exists_dir(p: &str) -> Result<bool> {
    let md = match std::fs::metadata(p) {
        Ok(md) => md,
        Err(e) => match e.kind() {
            ErrorKind::NotFound => return Ok(false),
            _ => bail!("checking {}: {}", p, e),
        },
    };

    if !md.is_dir() {
        bail!("\"{}\" exists but is not a directory", p);
    }

    Ok(true)
}

pub fn exists_file(p: &str) -> Result<bool> {
    let md = match std::fs::metadata(p) {
        Ok(md) => md,
        Err(e) => match e.kind() {
            ErrorKind::NotFound => return Ok(false),
            _ => bail!("checking {}: {}", p, e),
        },
    };

    if !md.is_file() {
        bail!("\"{}\" exists but is not a file", p);
    }

    Ok(true)
}


pub fn read_lines(p: &str) -> Result<Option<Vec<String>>> {
    Ok(read_file(p)?.map(|data| {
        data.lines().map(|a| a.trim().to_string()).collect()
    }))
}

pub fn read_lines_maybe(p: &str) -> Result<Vec<String>> {
    Ok(match read_lines(p)? {
        None => Vec::new(),
        Some(l) => l,
    })
}

pub

fn read_file(p: &str) -> Result<Option<String>> {
    let f = match File::open(p) {
        Ok(f) => f,
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::NotFound => return Ok(None),
                _ => bail!("open \"{}\": {}", p, e),
            };
        }
    };
    let mut r = std::io::BufReader::new(f);
    let mut out = String::new();
    r.read_to_string(&mut out)?;
    Ok(Some(out))
}

pub fn write_file(p: &str, data: &str) -> Result<()> {
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(p)?;
    let mut w = std::io::BufWriter::new(f);
    w.write_all(data.as_bytes())?;
    Ok(())
}

pub fn write_lines<L>(log: &Logger, p: &str, lines: &[L]) -> Result<()>
    where L: AsRef<str> + std::fmt::Debug
{
    info!(log, "----- WRITE FILE: {} ------ {:#?}", p, lines);
    let mut out = String::new();
    for l in lines {
        out.push_str(l.as_ref());
        out.push_str("\n");
    }
    write_file(p, &out)
}