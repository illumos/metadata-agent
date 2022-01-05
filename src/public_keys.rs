use crate::common::*;
use crate::file::*;

pub fn ensure_pubkeys(log: &Logger, user: &str, public_keys: &[String]) -> Result<(), failure::Error> {
    /*
     * Manage the public keys:
     */
    info!(log, "checking SSH public keys for user {}...", user);

    let sshdir = if user == "root" {
        format!("/root/.ssh")
    } else {
        format!("/export/home/{}/.ssh", user)
    };

    ensure_dir(log, &sshdir)?;

    let authorized_keys = sshdir + "/authorized_keys";

    let mut file = read_lines_maybe(&authorized_keys)?;
    info!(log, "existing SSH public keys: {:#?}", &file);

    let mut dirty = false;
    for key in public_keys.iter() {
        if !file.contains(key) {
            info!(log, "add SSH public key: {}", key);
            file.push(key.to_string());
            dirty = true;
        }
    }

    if dirty {
        write_lines(log, &authorized_keys, file.as_ref())?;
    }

    Ok(())
}