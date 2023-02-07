// Add this as we havent structured the crates very nicely for two binaries
#[allow(dead_code)]
mod common;
// Add this as we havent structured the crates very nicely for two binaries
#[allow(dead_code)]
mod file;
// Add this as we havent structured the crates very nicely for two binaries
#[allow(dead_code)]
mod userdata;

use anyhow::Result;
use base64::decode as base64Decode;
use common::*;
use flate2::read::GzDecoder;
use libc;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::Error as IOError;
use std::io::Result as IOResult;
use std::io::{copy as IOCopy, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;

use file::*;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use userdata::cloudconfig::*;
use userdata::multiformat_deserialize::*;
use userdata::*;

const UNPACKDIR: &str = "/var/metadata/files";
const PKG: &str = "/usr/bin/pkg";
const USERADD: &str = "/usr/sbin/useradd";
const GROUPADD: &str = "/usr/sbin/groupadd";
const USERMOD: &str = "/usr/sbin/usermod";
const USERSCRIPT: &str = "/var/metadata/userscript";
const FMRI_USERSCRIPT: &str = "svc:/system/illumos/userscript:default";
const SVCADM: &str = "/usr/sbin/svcadm";

fn main() -> Result<()> {
    let log = init_log();

    /*
     * This program could be destructive if run in the wrong place.  Try to
     * ensure it has at least been installed as an SMF service:
     */
    if let Some(fmri) = std::env::var_os("SMF_FMRI") {
        info!(log, "SMF instance: {}", fmri.to_string_lossy());
    } else {
        bail!("SMF_FMRI is not set; running under SMF?");
    }

    let dir_buf = PathBuf::from(UNPACKDIR);

    let user_data_path = dir_buf.join("user-data");

    if !user_data_path.exists() {
        return Ok(());
    }

    let user_data = read_user_data(&log, &user_data_path)?;

    /*
     * User data phase
     */
    phase_user_data(&log, &user_data)?;

    for script in user_data.scripts {
        /*
         * handle the userscripts we have in the user-data:
         */
        phase_userscript(&log, &script)?;
    }

    Ok(())
}

fn phase_user_data(log: &Logger, user_data: &UserData) -> Result<()> {
    //First Apply cloud configurations
    for cc in user_data.cloud_configs.clone() {
        /*
         * First Apply the groups
         */
        if let Some(groups) = cc.groups {
            for group in groups {
                ensure_group(log, group)?;
            }
        }

        for user in cc.users {
            ensure_user(log, &user)?;
        }

        if let Some(files) = cc.write_files {
            for file in files {
                ensure_write_file(log, &file)?;
            }
        }

        /*
        if let Some(ca_certs) = cc.ca_certs {

        }
        */

        if let Some(packages) = cc.packages {
            match packages {
                Multiformat::String(pkg) => {
                    ensure_packages(&log, vec![pkg])?;
                }
                Multiformat::List(pkgs) => {
                    ensure_packages(&log, pkgs)?;
                }
                _ => {}
            }
        }

        /*
         * Set general ssh Authorized keys
         */
        if let Some(keys) = cc.ssh_authorized_keys {
            ensure_pubkeys(log, "root", &keys)?;
        }
    }

    //Then run the scripts

    Ok(())
}

fn ensure_packages(log: &&Logger, pkgs: Vec<String>) -> Result<()> {
    info!(log, "installing packages {:#?}", pkgs);
    let mut pkg_cmd = Command::new(PKG);
    pkg_cmd.env_clear();
    pkg_cmd.arg("install");
    pkg_cmd.arg("-v");

    for pkg in pkgs {
        pkg_cmd.arg(pkg);
    }

    let mut child = pkg_cmd.spawn()?;
    let status = child.wait()?;
    if !status.success() {
        bail!("failed package installation see log messages above")
    }

    info!(log, "packages installed");
    Ok(())
}

fn ensure_write_file(log: &Logger, file: &WriteFileData) -> Result<()> {
    info!(log, "creating file {}", file.path);
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&file.path)?;
    let mut w = std::io::BufWriter::new(&f);

    match file.encoding {
        WriteFileEncoding::None => {
            trace!(log, "writing string data");
            w.write_all(file.content.as_bytes())?;
        }
        WriteFileEncoding::B64 => {
            trace!(log, "writing base64 encoded data");
            w.write_all(base64Decode(&file.content)?.as_slice())?;
        }
        WriteFileEncoding::Gzip => {
            trace!(log, "writing gzip encoded data");
            let content_clone = file.content.clone();
            let mut conent_bytes = content_clone.as_str().as_bytes();
            let mut d = GzDecoder::new(BufReader::new(&mut conent_bytes));
            IOCopy(&mut d, &mut w)?;
        }
        WriteFileEncoding::B64Gzip => {
            trace!(log, "writing gzipped base64 encoded data");
            let decoded_content = base64Decode(&file.content)?;
            let mut d = GzDecoder::new(decoded_content.as_slice());
            IOCopy(&mut d, &mut w)?;
        }
    }

    if let Some(mode_string) = &file.permissions {
        info!(
            log,
            "setting permissions of file {} to {}", file.path, mode_string
        );
        let meta = &f.metadata()?;
        let mut perms = meta.permissions();
        perms.set_mode(mode_string.parse::<u32>()?);
    }

    if let Some(owner) = &file.owner {
        info!(
            log,
            "setting owner and group of file {} to {}", file.path, owner
        );
        #[allow(unused_mut)]
        let mut uid: users::uid_t;
        #[allow(unused_mut)]
        let mut gid: users::gid_t;
        if owner.contains(":") {
            if let Some((u, g)) = owner.split_once(":") {
                if let Some(user) = users::get_user_by_name(u) {
                    uid = user.uid();
                } else {
                    bail!("could not find user {} in system", u)
                }

                if let Some(group) = users::get_group_by_name(g) {
                    gid = group.gid();
                } else {
                    bail!("could not find group {} in system", g)
                }
            } else {
                bail!("wrong user group string invalid config")
            }
        } else {
            let meta = f.metadata()?;
            gid = meta.gid();
            if let Some(u) = users::get_user_by_name(&owner) {
                uid = u.uid();
            } else {
                bail!("could not find user {} in system", &owner)
            }
        }
        chown(&file.path, uid, gid, false)?;
    }

    Ok(())
}

/// Actually perform the change of owner on a path
fn chown<P: AsRef<Path>>(
    path: P,
    uid: libc::uid_t,
    gid: libc::gid_t,
    follow: bool,
) -> IOResult<()> {
    let path = path.as_ref();
    let s = CString::new(path.as_os_str().as_bytes()).unwrap();
    let ret = unsafe {
        if follow {
            libc::chown(s.as_ptr(), uid, gid)
        } else {
            libc::lchown(s.as_ptr(), uid, gid)
        }
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(IOError::last_os_error())
    }
}

fn ensure_pubkeys(log: &Logger, user: &str, public_keys: &[String]) -> Result<()> {
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

    let authorized_keys = sshdir.clone() + "/authorized_keys";

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

        if let Some(usr) = users::get_user_by_name(&user) {
            chown(
                Path::new(sshdir.as_str()),
                usr.uid(),
                usr.primary_group_id(),
                false,
            )?;
            chown(
                Path::new(authorized_keys.as_str()),
                usr.uid(),
                usr.primary_group_id(),
                false,
            )?;
        }
    }

    Ok(())
}

fn ensure_user(log: &Logger, user: &UserConfig) -> Result<()> {
    if users::get_user_by_name(&user.name).is_none() {
        let mut cmd = Command::new(USERADD);
        if let Some(groups) = &user.groups {
            cmd.arg("-G").arg(groups.join(","));
        }

        if let Some(expire_date) = &user.expire_date {
            cmd.arg("-e").arg(expire_date);
        }

        if let Some(gecos) = &user.gecos {
            cmd.arg("-c").arg(gecos);
        }

        if let Some(home_dir) = &user.homedir {
            cmd.arg("-d").arg(home_dir);
        }

        if let Some(primary_group) = &user.primary_group {
            cmd.arg("-g").arg(primary_group);
        } else if let Some(no_user_group) = &user.no_user_group {
            if !no_user_group {
                let mut ump = HashMap::<String, Option<Vec<String>>>::new();
                ump.insert(user.name.clone(), Some(vec![]));
                ensure_group(log, ump)?;
            }
        }

        if let Some(inactive) = &user.inactive {
            cmd.arg("-f").arg(inactive);
        }

        if let Some(shell) = &user.shell {
            cmd.arg("-s").arg(shell);
        }

        cmd.arg("-m");

        cmd.arg(&user.name);

        //TODO lock_passwd
        //TODO passwd
        //TODO is_system_user
        debug!(log, "Running useradd {:?}", cmd);
        let output = cmd.output()?;
        if !output.status.success() {
            bail!("useradd failed for {}: {}", &user.name, output.info());
        }

        debug!(log, "Running passwd -N {}", &user.name);
        let passwd_out = Command::new("passwd").arg("-N").arg(&user.name).output()?;
        if !passwd_out.status.success() {
            bail!(
                "unlocking user {} failed: {}",
                &user.name,
                passwd_out.info()
            );
        }
    } else {
        info!(log, "user with name {} exists skipping", &user.name);
    }

    if let Some(public_keys) = &user.ssh_authorized_keys {
        ensure_pubkeys(log, &user.name, public_keys)?;
    }

    Ok(())
}

fn ensure_group(log: &Logger, groups: HashMap<String, Option<Vec<String>>>) -> Result<()> {
    for (group_name, users_in_group_opt) in groups {
        if users::get_group_by_name(&group_name).is_none() {
            let mut cmd = Command::new(GROUPADD);
            cmd.arg(&group_name);
            debug!(log, "Running groupadd {:?}", cmd);
            let output = cmd.output()?;
            if !output.status.success() {
                bail!("groupadd failed for {}: {}", &group_name, output.info());
            }
        } else {
            info!(log, "group {} exists", group_name)
        }

        if let Some(users_in_group) = users_in_group_opt {
            for user in users_in_group {
                let existing_groups: Vec<String> =
                    if let Some(sys_user) = users::get_user_by_name(&user) {
                        if let Some(user_groups) =
                            users::get_user_groups(&user, sys_user.primary_group_id())
                        {
                            user_groups
                                .iter()
                                .map(|g| {
                                    g.name()
                                        .to_os_string()
                                        .into_string()
                                        .unwrap_or(String::new())
                                })
                                .collect()
                        } else {
                            vec![]
                        }
                    } else {
                        vec![]
                    };

                let mut user_groups: Vec<String> = existing_groups
                    .iter()
                    .filter(|&g| g.clone() != String::new())
                    .map(|g| g.clone())
                    .collect();

                user_groups.push(group_name.clone());
                let mut cmd = Command::new(USERMOD);
                cmd.arg("-G");
                cmd.arg(user_groups.clone().join(","));
                cmd.arg(&user);
                debug!(log, "Running usermod {:?}", cmd);
                let output = cmd.output()?;
                if !output.status.success() {
                    bail!("usermod failed for {}: {}", &user, output.info());
                }
            }
        }
    }

    Ok(())
}

fn phase_userscript(log: &Logger, userscript: &str) -> Result<()> {
    /*
     * If the userscript is basically empty, just ignore it.
     */
    if userscript.trim().is_empty() {
        return Ok(());
    }

    /*
     * First check to see if this is a script with an interpreter line that has
     * an absolute path; i.e., begins with "#!/".  If not, we will assume it is
     * in some format we do not understand for now (like the cloud-init format,
     * etc).
     */
    if !userscript.starts_with("#!/") {
        bail!("userscript does not start with an #!/interpreter line");
    }

    let us2;
    let filedata = if !userscript.is_empty() && !userscript.ends_with('\n') {
        /*
         * UNIX text files should end with a newline.
         */
        us2 = format!("{}\n", userscript);
        &us2
    } else {
        userscript
    };

    /*
     * Write userscript to a file, ensuring it is root:root 0700.
     */
    write_file(USERSCRIPT, filedata)?;

    /*
     * Make sure the userscript is executable.
     */
    let mut perms = fs::metadata(USERSCRIPT)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(USERSCRIPT, perms)?;

    /*
     * Enable the svc:/system/illumos/userscript:default SMF instance.
     */
    smf_enable(log, FMRI_USERSCRIPT)?;

    Ok(())
}

fn smf_enable(log: &Logger, fmri: &str) -> Result<()> {
    info!(log, "exec: svcadm enable {}", fmri);
    let output = Command::new(SVCADM)
        .env_clear()
        .arg("enable")
        .arg(fmri)
        .output()?;

    if !output.status.success() {
        bail!("svcadm enable {} failed: {}", fmri, output.info());
    }

    Ok(())
}
