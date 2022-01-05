use std::collections::HashMap;
use crate::common::*;
use crate::userdata::cloudconfig::UserConfig;

#[cfg(feature = "libc_users")]
mod libc;
#[cfg(feature = "libc_users")]
use libc::ensure_group as real_ensure_group;
#[cfg(feature = "libc_users")]
use ffi::ensure_user as real_ensure_user;

#[cfg(feature = "cmd_users")]
mod ffi;
#[cfg(feature = "cmd_users")]
use ffi::ensure_group as real_ensure_group;
#[cfg(feature = "cmd_users")]
use ffi::ensure_user as real_ensure_user;

pub fn ensure_group(group: HashMap<String, Option<Vec<String>>>) -> Result<(), failure::Error> {
    real_ensure_group(group)
}

pub fn ensure_user(log: &Logger, user: &UserConfig) -> Result<(), failure::Error> {
    real_ensure_user(log, user)
}