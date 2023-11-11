/*
 * Copyright 2023 Oxide Computer Company
 */

use std::collections::HashMap;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

use super::prelude::*;

pub fn run(log: &Logger, smbios_uuid: &str) -> Result<()> {
    /*
     * Load our stamp file to see if the Guest UUID has changed.
     */
    if let Some([id]) = read_lines(STAMP)?.as_deref() {
        if id.trim() == smbios_uuid {
            info!(
                log,
                "this guest has already completed first \
                boot processing, halting"
            );
            return Ok(());
        } else {
            info!(
                log,
                "guest UUID changed ({} -> {}), reprocessing",
                id.trim(),
                smbios_uuid
            );
        }
    }

    phase_reguid_zpool(log)?;

    /*
     * To ease configuration of a guest on a system that lacks a mechanism for
     * guest metadata services (e.g., QEMU under libvirt on a Linux desktop or
     * VMware Fusion on a Macintosh) we will try to detect a disk device that
     * contains a cpio archive with metadata files.
     */
    info!(log, "searching for cpio device with metadata...");
    let dev = find_cpio_device(log)?;
    if let Some(dev) = &dev {
        println!("extracting cpio from {} to {}", dev, UNPACKDIR);
        ensure_dir(log, UNPACKDIR)?;
        let cpio = Command::new(CPIO)
            .arg("-i")
            .arg("-q")
            .arg("-I")
            .arg(dev)
            .current_dir(UNPACKDIR)
            .env_clear()
            .output()?;

        if !cpio.status.success() {
            bail!("cpio failure: {}", cpio.info());
        }

        info!(log, "ok, cpio extracted");
    }

    /*
     * The archive may contain a configuration file that influences our
     * behaviour.
     */
    let c: Config =
        read_toml(&format!("{}/config.toml", UNPACKDIR))?.unwrap_or_default();

    /*
     * Get a system hostname from the archive, if provided.  Make sure to set
     * this before engaging DHCP, so that "virsh net-dhcp-leases default" can
     * display the hostname in the lease record instead of "unknown".
     */
    let name = format!("{}/nodename", UNPACKDIR);
    if let Some(name) = read_file(&name)? {
        phase_set_hostname(log, name.trim())?;
    }

    /*
     * Get SSH public keys from the archive, if provided.  Do this before we try
     * to configure networking, in case that is partially successful and having
     * the keys in place would be helpful for debugging.
     */
    let keys = format!("{}/authorized_keys", UNPACKDIR);
    if let Some(keys) = read_lines(&keys)? {
        phase_pubkeys(log, keys.as_slice())?;
    }

    if !c.network.skip {
        /*
         * For now, we will configure one NIC with DHCP.  Virtio interfaces are
         * preferred.
         */
        let ifaces = dladm_ether_list()?;
        let mut chosen = None;
        info!(log, "found these ethernet interfaces: {:?}", ifaces);
        /*
         * Prefer Virtio devices:
         */
        for iface in ifaces.iter() {
            if iface.starts_with("vioif") {
                chosen = Some(iface.as_str());
                break;
            }
        }
        /*
         * Otherwise, use whatever we have:
         */
        if chosen.is_none() {
            chosen = ifaces.first().map(|x| x.as_str());
        }

        if let Some(chosen) = chosen {
            info!(log, "chose interface {}", chosen);
            ensure_ipv4_interface_dhcp(log, "dhcp", chosen)?;
        } else {
            bail!("could not find an appropriate Ethernet interface!");
        }
    }

    /*
     * Get a user-provided first boot script from the archive, if provided:
     */
    let script = format!("{}/firstboot.sh", UNPACKDIR);
    if let Some(script) = read_file(&script)? {
        phase_userscript(log, &script)?;
    }

    write_lines(log, STAMP, &[smbios_uuid])?;

    Ok(())
}

fn detect_archive<P: AsRef<Path>>(rdevpath: P) -> Result<Option<String>> {
    let mut buf = [0u8; 512];
    let mut f = OpenOptions::new()
        .read(true)
        .write(false)
        .append(false)
        .truncate(false)
        .open(rdevpath.as_ref())?;
    f.read_exact(&mut buf)?;
    if buf[0] == 0xC7 && buf[1] == 0x71 {
        /*
         * Binary header (octal 070707)
         */
        Ok(Some("cpio".to_string()))
    } else if &buf[0..6] == b"070707" {
        /*
         * ASCII header
         */
        Ok(Some("cpio".to_string()))
    } else {
        Ok(None)
    }
}

fn find_cpio_device(log: &Logger) -> Result<Option<String>> {
    /*
     * Use the raw device so that we can read just enough bytes to look for the
     * cpio magic:
     */
    let i = std::fs::read_dir("/dev/rdsk")?;

    let mut out = Vec::new();

    for ent in i {
        let ent = ent?;

        if let Some(name) = ent.file_name().to_str() {
            if !name.ends_with("p0") {
                continue;
            }
        } else {
            continue;
        }

        match detect_archive(&ent.path()) {
            Ok(Some(archive)) => {
                if &archive == "cpio" {
                    out.push(ent.path());
                }
            }
            Err(e) => warn!(
                log,
                "detecting archive on {}: {:?}",
                ent.path().display(),
                e
            ),
            _ => {}
        }
    }

    match out.len() {
        0 => Ok(None),
        1 => Ok(Some(out[0].to_str().unwrap().to_string())),
        n => bail!("found {} cpio archive devices", n),
    }
}

pub fn cpio_probe(log: &Logger) -> Result<bool> {
    Ok(find_cpio_device(log)?.is_some())
}
