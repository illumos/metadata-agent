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

fn amazon_metadata_getx(log: &Logger, key: &str) -> Result<Option<String>> {
    let url = format!("http://169.254.169.254/latest/{}", key);

    let cb = reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    loop {
        match cb.get(&url).send() {
            Ok(res) => {
                if res.status().is_success() {
                    let val = res.text()?.trim_end_matches('\n').to_string();
                    return Ok(Some(val));
                } else if res.status().as_u16() == 404 {
                    return Ok(None);
                }

                error!(log, "metadata {}: bad status {}", key, res.status());
            }
            Err(e) => {
                error!(log, "metadata {}: bad status {}", key, e);
            }
        }

        sleep(5_000);
    }
}

fn amazon_metadata_get(log: &Logger, key: &str) -> Result<Option<String>> {
    amazon_metadata_getx(log, &format!("meta-data/{}", key))
}

pub fn run(log: &Logger) -> Result<()> {
    /*
     * Sadly, Amazon has no mechanism for metadata access that does not require
     * a correctly configured IP interface.  In addition, the available NIC
     * depends on at least the instance type, if not other configuration.  Find
     * the right interface for DHCP:
     */
    let ifaces = dladm_ether_list()?;
    let mut chosen = None;
    info!(log, "found these ethernet interfaces: {:?}", ifaces);
    /*
     * Prefer ENA devices:
     */
    for iface in ifaces.iter() {
        if iface.starts_with("ena") {
            chosen = Some(iface.as_str());
            break;
        }
    }
    /*
     * If there is no ENA, try for a Xen interface:
     */
    if chosen.is_none() {
        for iface in ifaces.iter() {
            if iface.starts_with("xnf") {
                chosen = Some(iface.as_str());
                break;
            }
        }
    }
    /*
     * Otherwise, use whatever we have:
     */
    if chosen.is_none() {
        chosen = ifaces.first().map(|x| x.as_str());
    }

    let Some(chosen) = chosen else {
        bail!("could not find an appropriate Ethernet interface!");
    };

    info!(log, "chose interface {}", chosen);
    ensure_ipv4_interface_dhcp(log, "dhcp", chosen)?;

    /*
     * Determine the instance ID, using the metadata service:
     */
    let instid = if let Some(id) = amazon_metadata_get(log, "instance-id")? {
        id
    } else {
        bail!("could not determine instance ID");
    };

    /*
     * Load our stamp file to see if the Instance ID has changed.
     */
    if let Some([id]) = read_lines(STAMP)?.as_deref() {
        if id.trim() == instid {
            info!(
                log,
                "this guest has already completed first \
                boot processing, halting"
            );
            return Ok(());
        } else {
            info!(
                log,
                "guest Instance ID changed ({} -> {}), reprocessing",
                id.trim(),
                instid,
            );
        }
    }

    phase_reguid_zpool(log)?;

    /*
     * Determine the node name for this guest:
     */
    let (src, n) =
        if let Some(hostname) = dhcpinfo(log, "hostname", Some(chosen))? {
            ("DHCP", hostname.trim().to_string())
        } else if let Some(hostname) = amazon_metadata_get(log, "hostname")? {
            ("metadata", hostname.trim().to_string())
        } else {
            bail!("could not get hostname for this VM");
        };
    info!(log, "VM node name is \"{}\" (from {})", n, src);
    phase_set_hostname(log, &n)?;

    /*
     * Get public key:
     */
    if let Some(pk) = amazon_metadata_get(log, "public-keys/0/openssh-key")? {
        let pubkeys = vec![pk];
        phase_pubkeys(log, &pubkeys)?;
    } else {
        warn!(log, "no SSH public key?");
    }

    /*
     * Get user script:
     */
    if let Some(userscript) = amazon_metadata_getx(log, "user-data")? {
        phase_userscript(log, &userscript)
            .map_err(|e| error!(log, "failed to get user-script: {}", e))
            .ok();
    } else {
        info!(log, "no user-data?");
    }

    write_lines(log, STAMP, &[instid])?;

    Ok(())
}
