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

const MDATA_GET: &str = "/usr/sbin/mdata-get";

#[allow(unused)]
#[derive(Debug, Deserialize)]
struct SdcNic {
    mac: String,
    interface: String,
    #[serde(default)]
    ips: Vec<String>,
    #[serde(default)]
    gateways: Vec<String>,
    primary: Option<bool>,
    nic_tag: Option<String>,
}

impl SdcNic {
    fn primary(&self) -> bool {
        self.primary.unwrap_or(false)
    }
}

pub fn run(log: &Logger) -> Result<()> {
    let uuid = if let Mdata::Found(uuid) = mdata_get(log, "sdc:uuid")? {
        uuid.trim().to_string()
    } else {
        bail!("could not read Guest UUID");
    };

    /*
     * Load our stamp file to see if the Guest UUID has changed.
     */
    if let Some([id]) = read_lines(STAMP)?.as_deref() {
        if id.trim() == uuid {
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
                uuid
            );
        }
    }

    phase_reguid_zpool(log)?;

    /*
     * Determine the node name for this guest:
     */
    let n = if let Mdata::Found(hostname) = mdata_get(log, "sdc:hostname")? {
        hostname
    } else if let Mdata::Found(alias) = mdata_get(log, "sdc:alias")? {
        alias
    } else if let Mdata::Found(uuid) = mdata_get(log, "sdc:uuid")? {
        uuid
    } else {
        bail!("could not get hostname or alias or UUID for this VM");
    }
    .trim()
    .to_string();
    info!(log, "VM node name is \"{}\"", n);
    phase_set_hostname(log, &n)?;

    /*
     * Get network configuration:
     */
    if let Mdata::Found(nics) = mdata_get(log, "sdc:nics")? {
        let nics: Vec<SdcNic> = serde_json::from_str(&nics)?;

        for nic in nics.iter() {
            for (i, ip) in nic.ips.iter().enumerate() {
                if ip == "dhcp" || ip == "addrconf" {
                    /*
                     * XXX handle these.
                     */
                    error!(
                        log,
                        "interface {} requires {} support", nic.interface, ip
                    );
                    continue;
                }

                let sfx = format!("ip{}", i);

                if let Err(e) = ensure_ipv4_interface(log, &sfx, &nic.mac, ip) {
                    error!(log, "IFACE {}/{} ERROR: {}", nic.interface, sfx, e);
                }
            }

            if nic.primary() {
                for gw in nic.gateways.iter() {
                    if let Err(e) = ensure_ipv4_gateway(log, gw) {
                        error!(log, "PRIMARY GATEWAY {} ERROR: {}", gw, e);
                    }
                }
            }
        }
    }

    /*
     * Get DNS servers:
     */
    if let Mdata::Found(resolvers) = mdata_get(log, "sdc:resolvers")? {
        let resolvers: Vec<String> = serde_json::from_str(&resolvers)?;

        phase_dns(log, &resolvers, &[])?;
    }

    /*
     * Get public keys:
     */
    if let Mdata::Found(pubkeys) = mdata_get(log, "root_authorized_keys")? {
        let pubkeys: Vec<String> =
            pubkeys.lines().map(|s| s.trim().to_string()).collect();

        phase_pubkeys(log, &pubkeys)?;
    }

    /*
     * Get userscript:
     */
    if let Mdata::Found(userscript) = mdata_get(log, "user-script")? {
        phase_userscript(log, &userscript)
            .map_err(|e| error!(log, "failed to get user-script: {}", e))
            .ok();
    }

    write_lines(log, STAMP, &[uuid])?;

    Ok(())
}

enum Mdata {
    Found(String),
    NotFound,
    WrongHypervisor,
}

fn mdata_get(log: &Logger, key: &str) -> Result<Mdata> {
    info!(log, "mdata-get \"{}\"...", key);
    let output = Command::new(MDATA_GET).env_clear().arg(key).output()?;

    Ok(match output.status.code() {
        Some(0) => {
            let out = String::from_utf8(output.stdout)?
                .trim_end_matches('\n')
                .to_string();
            info!(log, "mdata for \"{}\" -> \"{}\"", key, out);
            Mdata::Found(out)
        }
        Some(1) => {
            warn!(log, "mdata for \"{}\" not found", key);
            Mdata::NotFound
        }
        Some(2) => {
            /*
             * An unexpected permanent failure occurred, which likely means we
             * cannot use "mdata-get" for metadata on this system.  Assume this
             * is not a SmartOS system.
             */
            warn!(log, "mdata wrong hypervisor: {}", output.info());
            Mdata::WrongHypervisor
        }
        _ => bail!("mdata-get: unexpected failure: {}", output.info()),
    })
}

pub fn mdata_probe(log: &Logger) -> Result<bool> {
    /*
     * Check for an mdata-get(8) binary on this system:
     */
    if !exists_file(MDATA_GET)? {
        /*
         * If the program is not there at all, this is not an image for a guest
         * on a SmartOS hypervisor.
         */
        return Ok(false);
    }

    match mdata_get(log, "sdc:uuid")? {
        Mdata::Found(_) | Mdata::NotFound => {
            /*
             * Whether found or not found, we were able to speak to the
             * hypervisor.  Treat this as a SmartOS system.
             */
            Ok(true)
        }
        Mdata::WrongHypervisor => {
            /*
             * An unexpected permanent failure occurred, which likely means we
             * cannot use "mdata-get" for metadata on this system.  Assume this
             * is not a SmartOS system.
             */
            Ok(false)
        }
    }
}
