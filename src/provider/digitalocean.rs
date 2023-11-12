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

#[allow(unused)]
#[derive(Debug, Deserialize)]
struct FloatingIP {
    active: bool,
}

#[derive(Debug, Deserialize)]
struct IPv4 {
    ip_address: String,
    gateway: String,
    netmask: String,
}

impl IPv4 {
    fn prefix_len(&self) -> Result<u32> {
        let nm: Ipv4Addr = self.netmask.parse()?;
        netmask_to_prefix_len(nm)
    }

    fn cidr(&self) -> Result<String> {
        let prefix_len = self.prefix_len()?;
        Ok(format!("{}/{}", self.ip_address, prefix_len))
    }
}

#[derive(Debug, Deserialize)]
struct Interface {
    anchor_ipv4: Option<IPv4>,
    ipv4: IPv4,
    mac: String,
    #[serde(rename = "type")]
    type_: String,
}

#[derive(Debug, Deserialize)]
struct Interfaces {
    public: Option<Vec<Interface>>,
    private: Option<Vec<Interface>>,
}

#[derive(Debug, Deserialize)]
struct Dns {
    nameservers: Vec<String>,
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
struct Metadata {
    auth_key: String,
    dns: Dns,
    droplet_id: u64,
    floating_ip: FloatingIP,
    interfaces: Interfaces,
    hostname: String,
    public_keys: Vec<String>,
    region: String,
    features: HashMap<String, bool>,
    user_data: Option<String>,
}

pub fn run(log: &Logger) -> Result<()> {
    /*
     * First, locate and mount the metadata ISO.  We need to load the droplet ID
     * so that we can determine if we have completed first boot processing for
     * this droplet or not.
     */
    let mounts = mounts()?;
    let mdmp: Vec<_> =
        mounts.iter().filter(|m| m.mount_point == MOUNTPOINT).collect();

    let do_mount = match mdmp.as_slice() {
        [] => true,
        [m] => {
            /*
             * Check the existing mount to see if it is adequate.
             */
            if m.fstype != "hsfs" {
                bail!("INVALID MOUNTED FILE SYSTEM: {:#?}", m);
            }
            false
        }
        m => {
            bail!("found these mounts for {}: {:#?}", MOUNTPOINT, m);
        }
    };

    if do_mount {
        info!(log, "need to mount Metadata ISO");

        ensure_dir(log, MOUNTPOINT)?;

        let dev = if let Some(dev) = find_device("hsfs", None)? {
            dev
        } else {
            bail!("no hsfs file system found");
        };

        let output = Command::new(MOUNT)
            .env_clear()
            .arg("-F")
            .arg("hsfs")
            .arg(dev)
            .arg(MOUNTPOINT)
            .output()?;

        if !output.status.success() {
            bail!("mount: {}", output.info());
        }

        info!(log, "mount ok at {}", MOUNTPOINT);
    }

    /*
     * Read metadata from the file system:
     */
    let md: Option<Metadata> =
        read_json(&format!("{}/digitalocean_meta_data.json", MOUNTPOINT))?;

    let md = if let Some(md) = md {
        md
    } else {
        bail!("could not read metadata file");
    };

    info!(log, "metadata: {:#?}", md);

    /*
     * Load our stamp file to see if the Droplet ID has changed.
     */
    if let Some([id]) = read_lines(STAMP)?.as_deref() {
        let expected = md.droplet_id.to_string();

        if id.trim() == expected {
            info!(
                log,
                "this droplet has already completed first \
                boot processing, halting"
            );
            return Ok(());
        } else {
            info!(
                log,
                "droplet ID changed ({} -> {}), reprocessing",
                id.trim(),
                expected
            );
        }
    }

    phase_reguid_zpool(log)?;
    phase_set_hostname(log, &md.hostname)?;

    /*
     * Check network configuration:
     */
    for iface in md.interfaces.private.as_ref().unwrap_or(&vec![]).iter() {
        if iface.type_ != "private" {
            continue;
        }

        if let Err(e) = ensure_ipv4_interface(
            log,
            "private",
            &iface.mac,
            &iface.ipv4.cidr()?,
        ) {
            /*
             * Report the error, but drive on in case we can complete other
             * configuration and make the guest accessible anyway.
             */
            error!(log, "PRIV IFACE ERROR: {}", e);
        }
    }

    for iface in md.interfaces.public.as_ref().unwrap_or(&vec![]).iter() {
        if iface.type_ != "public" {
            continue;
        }

        if let Err(e) = ensure_ipv4_interface(
            log,
            "public",
            &iface.mac,
            &iface.ipv4.cidr()?,
        ) {
            /*
             * Report the error, but drive on in case we can complete other
             * configuration and make the guest accessible anyway.
             */
            error!(log, "PUB IFACE ERROR: {}", e);
        }

        if let Err(e) = ensure_ipv4_gateway(log, &iface.ipv4.gateway) {
            error!(log, "PUB GATEWAY ERROR: {}", e);
        }

        if let Some(anchor) = &iface.anchor_ipv4 {
            if let Err(e) = ensure_ipv4_interface(
                log,
                "anchor",
                &iface.mac,
                &anchor.cidr()?,
            ) {
                error!(log, "ANCHOR IFACE ERROR: {}", e);
            }
        }
    }

    phase_dns(log, &md.dns.nameservers, &[])?;
    phase_pubkeys(log, md.public_keys.as_slice())?;

    /*
     * Get userscript:
     */
    if let Some(userscript) = md.user_data.as_deref() {
        phase_userscript(log, userscript)
            .map_err(|e| error!(log, "failed to get user-script: {}", e))
            .ok();
    }

    write_lines(log, STAMP, &[md.droplet_id.to_string()])?;

    Ok(())
}

pub fn hsfs_probe() -> Result<bool> {
    Ok(find_device("hsfs", None)?.is_some())
}
