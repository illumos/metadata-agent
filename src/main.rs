/*
 * Copyright 2020 Oxide Computer Company
 * Copyright 2022 OpenFlowLabs
 *
 */

mod common;
mod file;
#[allow(dead_code)]
mod userdata;
mod zpool;

#[allow(dead_code)]
use crate::userdata::networkconfig::{NetworkDataV1Iface, NetworkDataV1Subnet};
use anyhow::Result;
use common::*;
use file::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read};
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const METADATA_DIR: &str = "/var/metadata";
const STAMP: &str = "/var/metadata/stamp";
const USERSCRIPT: &str = "/var/metadata/userscript";
const MOUNTPOINT: &str = "/var/metadata/iso";
const UNPACKDIR: &str = "/var/metadata/files";
const DEFROUTER: &str = "/etc/defaultrouter";
const DHCPINFO: &str = "/sbin/dhcpinfo";
const DLADM: &str = "/usr/sbin/dladm";
const FSTYP: &str = "/usr/sbin/fstyp";
const HOSTNAME: &str = "/usr/bin/hostname";
const IPADM: &str = "/usr/sbin/ipadm";
const MDATA_GET: &str = "/usr/sbin/mdata-get";
const MOUNT: &str = "/sbin/mount";
const PRTCONF: &str = "/usr/sbin/prtconf";
const SMBIOS: &str = "/usr/sbin/smbios";
const SVCADM: &str = "/usr/sbin/svcadm";
const SWAPADD: &str = "/sbin/swapadd";
const ZFS: &str = "/sbin/zfs";
const CPIO: &str = "/usr/bin/cpio";
const FMRI_USERSCRIPT: &str = "svc:/system/illumos/userscript:default";

#[derive(Debug)]
struct Smbios {
    manufacturer: String,
    product: String,
    version: String,
    uuid: String,
}

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

fn dhcpinfo(log: &Logger, key: &str) -> Result<Option<String>> {
    info!(log, "exec: dhcpinfo {}", key);
    let output = Command::new(DHCPINFO).env_clear().arg(key).output()?;

    if !output.status.success() {
        bail!("dhcpinfo {} failed: {}", key, output.info());
    }

    let out = String::from_utf8(output.stdout)?;
    let out = out.trim();
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out.to_string()))
    }
}

fn smbios(log: &Logger) -> Result<Option<Smbios>> {
    info!(log, "exec: smbios -t 1");
    let output = Command::new(SMBIOS)
        .env_clear()
        .arg("-t")
        .arg("1")
        .output()?;

    if !output.status.success() {
        let msg = String::from_utf8_lossy(&output.stderr);
        if msg.contains("System does not export an SMBIOS table") {
            Ok(None)
        } else {
            bail!("smbios -t 1 failure: {}", output.info());
        }
    } else {
        let mut m = "".to_string();
        let mut p = "".to_string();
        let mut v = "".to_string();
        let mut u = "".to_string();

        for l in String::from_utf8(output.stdout)?.lines() {
            let t: Vec<_> = l
                .trim()
                .splitn(2, ':')
                .map(|s| s.trim().to_string())
                .collect();

            if t.len() != 2 {
                continue;
            }

            let val = t[1].trim().to_string();

            match t[0].trim() {
                "Manufacturer" => m = val,
                "Product" => p = val,
                "Version" => v = val,
                "UUID" => u = val,
                _ => (),
            }
        }

        Ok(Some(Smbios {
            manufacturer: m,
            product: p,
            version: v,
            uuid: u,
        }))
    }
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

fn mdata_probe(log: &Logger) -> Result<bool> {
    /*
     * Check for an mdata-get(1M) binary on this system:
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

fn read_json<T>(p: &str) -> Result<Option<T>>
where
    for<'de> T: Deserialize<'de>,
{
    let s = read_file(p)?;
    match s {
        None => Ok(None),
        Some(s) => Ok(serde_json::from_str(&s)?),
    }
}

#[derive(Debug)]
enum MountOptionValue {
    Present,
    Value(String),
}

#[allow(dead_code)]
#[derive(Debug)]
struct Mount {
    special: String,
    mount_point: String,
    fstype: String,
    options: HashMap<String, MountOptionValue>,
    time: u64,
}

#[derive(Debug, Deserialize)]
struct DNS {
    nameservers: Vec<String>,
}

#[allow(dead_code)]
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
        let bits: u32 = nm.into();

        if bits.leading_zeros() != 0 {
            bail!("bits not left packed in {}", self.netmask);
        }

        let len = bits.count_ones();
        if bits.trailing_zeros() != 32 - len {
            bail!("bits not contiguous in {}", self.netmask);
        }
        assert_eq!(32 - len, bits.trailing_zeros());

        Ok(len)
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

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct DOMetadata {
    auth_key: String,
    dns: DNS,
    droplet_id: u64,
    floating_ip: FloatingIP,
    interfaces: Interfaces,
    hostname: String,
    public_keys: Vec<String>,
    region: String,
    features: HashMap<String, bool>,
    user_data: Option<String>,
}

#[allow(dead_code)]
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

/**
 * Read mnttab(4) and produce a list of mounts.  The result is a list instead of
 * a dictionary as there may be more than one mount entry for a particular mount
 * point.
 */
fn mounts() -> Result<Vec<Mount>> {
    let mnttab = read_lines("/etc/mnttab")?.unwrap();
    let rows: Vec<Vec<_>> = mnttab.iter().map(|m| m.split('\t').collect()).collect();

    assert!(rows.len() >= 5);

    let mut out = Vec::new();
    for r in rows {
        let mut options = HashMap::new();

        for p in r[3].split(',').collect::<Vec<&str>>() {
            let terms = p.splitn(2, '=').collect::<Vec<&str>>();

            let v = match terms.len() {
                1 => MountOptionValue::Present,
                2 => MountOptionValue::Value(terms[1].to_string()),
                n => panic!("{} terms?!", n),
            };

            options.insert(terms[0].to_string(), v);
        }

        out.push(Mount {
            special: r[0].to_string(),
            mount_point: r[1].to_string(),
            fstype: r[2].to_string(),
            options,
            time: r[4].parse().expect("mnttab time value"),
        });
    }

    Ok(out)
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

#[derive(Debug, Default, Clone)]
struct CiDataDevice {
    fstype: String,
    path: String,
    label: String,
}

fn find_cidata_devices(log: &Logger) -> Result<Option<Vec<CiDataDevice>>> {
    let i = std::fs::read_dir("/dev/dsk")?;

    let mut out: Vec<CiDataDevice> = Vec::new();

    for ent in i {
        let ent = ent?;

        if let Some(name) = ent.file_name().to_str() {
            if !name.ends_with("p0") && !name.ends_with("s0") {
                continue;
            }
        } else {
            continue;
        }

        /*
         * Determine which type of file system resides on the device:
         */
        let output = Command::new(FSTYP)
            .env_clear()
            .arg("-a")
            .arg(ent.path())
            .output()?;

        if !output.status.success() {
            continue;
        }

        let mut dev = CiDataDevice::default();
        dev.path = ent.path().to_str().unwrap().to_string();
        let mut count = 0;
        for line_result in BufReader::new(output.stdout.as_slice()).lines() {
            if let Ok(line) = line_result {
                if count == 0 {
                    dev.fstype = line.trim().to_lowercase().clone();
                }
                if line.contains(":") {
                    if let Some((key, value)) = line.split_once(":") {
                        if key.trim().to_lowercase() == "volume_label"
                            || key.trim().to_lowercase() == "volume_id"
                        {
                            let label = value.replace("'", "").trim().to_lowercase();
                            if label == "cidata" {
                                dev.label = label;
                                debug!(
                                    log,
                                    "found cidata device {} of type {}", &dev.path, &dev.fstype
                                );
                                out.push(dev.clone());
                            }
                        }
                    }
                }
                count += 1;
            }
        }
    }

    match out.len() {
        0 => Ok(None),
        _ => Ok(Some(out)),
    }
}

fn find_device() -> Result<Option<String>> {
    let i = std::fs::read_dir("/dev/dsk")?;

    let mut out = Vec::new();

    for ent in i {
        let ent = ent?;

        if let Some(name) = ent.file_name().to_str() {
            if !name.ends_with("p0") && !name.ends_with("s0") {
                continue;
            }
        } else {
            continue;
        }

        /*
         * Determine which type of file system resides on the device:
         */
        let output = Command::new(FSTYP).env_clear().arg(ent.path()).output()?;

        if !output.status.success() {
            continue;
        }

        if let Ok(s) = String::from_utf8(output.stdout) {
            if s.trim() == "hsfs" {
                out.push(ent.path());
            }
            if s.trim() == "pcfs" {
                out.push(ent.path());
            }
        }
    }

    match out.len() {
        0 => Ok(None),
        1 => Ok(Some(out[0].to_str().unwrap().to_string())),
        n => bail!("found {} hsfs file systems", n),
    }
}

struct Terms {
    terms: Vec<String>,
    buf: Option<String>,
}

impl Terms {
    fn append(&mut self, c: char) {
        if self.buf.is_none() {
            self.buf = Some(String::new());
        }
        self.buf.as_mut().unwrap().push(c);
    }

    fn commit(&mut self) {
        if let Some(val) = &self.buf {
            self.terms.push(val.to_string());
        }
        self.buf = None;
    }

    fn result(&self) -> Vec<String> {
        self.terms.to_owned()
        // self.terms.iter().map(|s| s.as_str()).collect()
    }

    fn new() -> Terms {
        Terms {
            terms: Vec::new(),
            buf: Some(String::new()),
        }
    }
}

fn parse_net_adm(stdout: Vec<u8>) -> Result<Vec<Vec<String>>> {
    let stdout = String::from_utf8(stdout)?;
    let mut out = Vec::new();

    for l in stdout.lines() {
        let mut terms = Terms::new();
        let mut escape = false;

        for c in l.chars() {
            if escape {
                terms.append(c);
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == ':' {
                terms.commit();
            } else {
                terms.append(c);
            }
        }
        terms.commit();

        out.push(terms.result());
    }

    Ok(out)
}

fn netmask_to_cidr(netmask: &Option<String>) -> Result<u8> {
    match netmask {
        None => Ok(24),
        Some(mask) => {
            let mask_parsed: Ipv4Addr = mask.parse()?;
            let octects = mask_parsed.octets();
            if octects[0] != 255 {
                match octects[0] {
                    128 => Ok(1),
                    192 => Ok(2),
                    224 => Ok(3),
                    240 => Ok(4),
                    248 => Ok(5),
                    252 => Ok(6),
                    254 => Ok(7),
                    _ => bail!("invalid netmask: {}", mask),
                }
            } else if octects[1] != 255 {
                match octects[1] {
                    0 => Ok(8),
                    128 => Ok(9),
                    192 => Ok(10),
                    224 => Ok(11),
                    240 => Ok(12),
                    248 => Ok(13),
                    252 => Ok(14),
                    254 => Ok(15),
                    _ => bail!("invalid netmask: {}", mask),
                }
            } else if octects[2] != 255 {
                match octects[2] {
                    0 => Ok(16),
                    128 => Ok(17),
                    192 => Ok(18),
                    224 => Ok(19),
                    240 => Ok(20),
                    248 => Ok(21),
                    252 => Ok(22),
                    254 => Ok(23),
                    _ => bail!("invalid netmask: {}", mask),
                }
            } else if octects[3] != 255 {
                match octects[3] {
                    0 => Ok(24),
                    128 => Ok(25),
                    192 => Ok(26),
                    224 => Ok(27),
                    240 => Ok(28),
                    248 => Ok(29),
                    252 => Ok(30),
                    254 => Ok(31),
                    _ => bail!("invalid netmask: {}", mask),
                }
            } else {
                Ok(32)
            }
        }
    }
}

fn ipadm_interface_list() -> Result<Vec<String>> {
    let output = Command::new(IPADM)
        .env_clear()
        .arg("show-if")
        .arg("-p")
        .arg("-o")
        .arg("ifname")
        .output()?;

    if !output.status.success() {
        bail!("ipadm failed: {}", output.info());
    }

    let ents = parse_net_adm(output.stdout)?;

    Ok(ents.iter().map(|ent| ent[0].to_string()).collect())
}

#[derive(Debug)]
struct IpadmAddress {
    name: String,
    type_: String,
    state: String,
    cidr: String,
}

fn ipadm_address_list() -> Result<Vec<IpadmAddress>> {
    let output = Command::new(IPADM)
        .env_clear()
        .arg("show-addr")
        .arg("-p")
        .arg("-o")
        .arg("addrobj,type,state,addr")
        .output()?;

    if !output.status.success() {
        bail!("ipadm failed: {}", output.info());
    }

    let ents = parse_net_adm(output.stdout)?;

    Ok(ents
        .iter()
        .map(|ent| IpadmAddress {
            name: ent[0].to_string(),
            type_: ent[1].to_string(),
            state: ent[2].to_string(),
            cidr: ent[3].to_string(),
        })
        .collect())
}

fn mac_sanitise(input: &str) -> String {
    let mac = input.split(':').fold(String::new(), |mut buf, octet| {
        if !buf.is_empty() {
            /*
             * Put the separating colon back between octets:
             */
            buf.push(':');
        }

        assert!(octet.len() == 1 || octet.len() == 2);
        if octet.len() < 2 {
            /*
             * Use a leading zero to pad any single-digit octets:
             */
            buf.push('0');
        }
        buf.push_str(&octet);

        buf
    });

    assert_eq!(mac.len(), 17);
    mac
}

fn dladm_ether_list() -> Result<Vec<String>> {
    let output = Command::new(DLADM)
        .env_clear()
        .arg("show-ether")
        .arg("-p")
        .arg("-o")
        .arg("link")
        .output()?;

    if !output.status.success() {
        bail!("dladm failed: {}", output.info());
    }

    let ents = parse_net_adm(output.stdout)?;
    Ok(ents.iter().map(|l| l[0].trim().to_string()).collect())
}

fn mac_to_nic(mac: &str) -> Result<Option<String>> {
    let output = Command::new(DLADM)
        .env_clear()
        .arg("show-phys")
        .arg("-m")
        .arg("-p")
        .arg("-o")
        .arg("link,address")
        .output()?;

    if !output.status.success() {
        bail!("dladm failed: {}", output.info());
    }

    let mut nics: HashMap<String, &str> = HashMap::new();

    let ents = parse_net_adm(output.stdout)?;
    for ent in ents.iter() {
        let mac = mac_sanitise(&ent[1]);

        if nics.contains_key(mac.as_str()) {
            bail!("MAC {} appeared on two NICs", &mac);
        }
        nics.insert(mac, &ent[0]);
    }

    if let Some(name) = nics.get(mac) {
        Ok(Some(name.to_string()))
    } else {
        Ok(None)
    }
}

fn memsize() -> Result<u64> {
    let output = std::process::Command::new(PRTCONF)
        .env_clear()
        .arg("-m")
        .output()?;

    if !output.status.success() {
        bail!("prtconf failed: {}", output.info());
    }

    Ok(String::from_utf8(output.stdout)?.trim().parse()?)
}

fn create_zvol(name: &str, size_mib: u64) -> Result<()> {
    let output = std::process::Command::new(ZFS)
        .env_clear()
        .arg("create")
        .arg("-V")
        .arg(format!("{}m", size_mib))
        .arg(name)
        .output()?;

    if !output.status.success() {
        bail!("zfs create failed: {}", output.info());
    }

    Ok(())
}

fn exists_zvol(name: &str) -> Result<bool> {
    let output = std::process::Command::new(ZFS)
        .env_clear()
        .arg("list")
        .arg("-Hp")
        .arg("-o")
        .arg("name,type")
        .output()?;

    if !output.status.success() {
        bail!("zfs list failed: {}", output.info());
    }

    let out = String::from_utf8(output.stdout)?;
    for l in out.lines() {
        let t: Vec<_> = l.split('\t').collect();
        assert_eq!(t.len(), 2);

        if t[0] != name {
            continue;
        }

        if t[1] != "volume" {
            bail!("dataset {} was of type {}, not volume", name, t[1]);
        }

        return Ok(true);
    }

    Ok(false)
}

fn swapadd() -> Result<()> {
    let output = std::process::Command::new(SWAPADD).env_clear().output()?;

    if !output.status.success() {
        bail!("swapadd failed: {}", output.info());
    }

    Ok(())
}

fn ensure_interface_name(log: &Logger, name: &str, mac_addres: &str) -> Result<()> {
    // First lets get the nic and check if we need to run.
    let nic = mac_to_nic(mac_addres)?;
    match nic {
        Some(iface) => {
            info!(log, "interface {} with mac {} found", &iface, mac_addres);
            // Rename the link if the current name is not what we expect
            if &iface != name {
                info!(log, "renaming link {} -> {}", &iface, name);
                let output = Command::new(DLADM)
                    .env_clear()
                    .arg("rename-link")
                    .arg(iface)
                    .arg(name)
                    .output()?;
                if !output.status.success() {
                    bail!("dladm rename-link returned an error: {}", output.info());
                }
            }
        }
        None => {
            bail!("could not find a nic with mac {}", mac_addres);
        }
    };

    Ok(())
}

fn ensure_ipadm_subnets_config(
    log: &Logger,
    link_name: &str,
    subnets: &Vec<NetworkDataV1Subnet>,
) -> Result<()> {
    info!(log, "configuring subnets for link {}", link_name);
    for subnet in subnets {
        if let Err(e) = ensure_ipadm_single_subnet_config(log, link_name, subnet) {
            error!(log, "error while configuring link {}: {}", link_name, e)
        }
    }

    Ok(())
}

fn ensure_ipadm_single_subnet_config(
    log: &Logger,
    link_name: &str,
    subnet: &NetworkDataV1Subnet,
) -> Result<()> {
    match subnet {
        NetworkDataV1Subnet::Dhcp4 | NetworkDataV1Subnet::Dhcp => {
            ensure_ipv4_interface_dhcp(log, "dhcp4", link_name)
        }
        NetworkDataV1Subnet::Dhcp6 | NetworkDataV1Subnet::Dhcpv6Stateful => {
            bail!("ipv6 is not implemented yet")
        }
        NetworkDataV1Subnet::Static(conf) => {
            if let Some(_) = &conf.netmask {
                let address = format!("{}/{}", conf.address, netmask_to_cidr(&conf.netmask)?);
                ensure_ipv4_interface(log, "ipv4", None, Some(link_name), &address)?;
            } else {
                let address = if !conf.address.contains("/") {
                    format!("{}/24", conf.address)
                } else {
                    conf.address.clone()
                };
                ensure_ipv4_interface(log, "ipv4", None, Some(link_name), &address)?;
            }

            if let Some(gw) = &conf.gateway {
                ensure_ipv4_gateway(log, gw)?;
            }

            if let Some(dns_servers) = &conf.dns_nameservers {
                ensure_dns_nameservers(log, dns_servers)?;
            }

            if let Some(dns_search) = &conf.dns_search {
                ensure_dns_search(log, dns_search)?;
            }

            if let Some(routes) = &conf.routes {
                error!(
                    log,
                    "route configuration not yet wupported, cannot apply {:#?} to link {}",
                    routes,
                    link_name
                );
            }

            Ok(())
        }
        NetworkDataV1Subnet::Static6(_) => {
            bail!("ipv6 is not implemented yet")
        }
        NetworkDataV1Subnet::Dhcpv6Stateless => {
            bail!("ipv6 is not implemented yet")
        }
        NetworkDataV1Subnet::SLAAC { .. } => {
            bail!("ipv6 is not implemented yet")
        }
    }
}

fn ensure_interface_mtu(log: &Logger, name: &str, mtu: &i32) -> Result<()> {
    info!(log, "setting mtu of interface {} to {}", name, mtu);
    let output = Command::new(DLADM)
        .env_clear()
        .arg("set-linkprop")
        .arg("-p")
        .arg(format!("mtu={}", mtu))
        .arg(name)
        .output()?;
    if !output.status.success() {
        bail!("dladm setting mtu failed: {}", output.info());
    }

    Ok(())
}

fn ensure_ipadm_interface(log: &Logger, n: &str) -> Result<bool> {
    info!(log, "ENSURE INTERFACE: {}", n);

    let ifaces = ipadm_interface_list()?;
    info!(log, "INTERFACES: {:#?}", &ifaces);

    if ifaces.contains(&n.to_string()) {
        info!(log, "interface {} exists already", n);
        Ok(false)
    } else {
        info!(log, "interface {} NEEDS CREATION", n);
        let output = Command::new(IPADM)
            .env_clear()
            .arg("create-if")
            .arg(n)
            .output()?;

        if !output.status.success() {
            bail!("ipadm create-if {}: {}", &n, output.info());
        }

        Ok(true)
    }
}

fn ensure_ipv4_gateway(log: &Logger, gateway: &str) -> Result<()> {
    info!(log, "ENSURE IPv4 GATEWAY: {}", gateway);

    let orig_defrouters = read_lines_maybe(DEFROUTER)?;
    let defrouters = &[gateway];
    info!(log, "existing default routers: {:?}", &orig_defrouters);

    if orig_defrouters.as_slice() != defrouters {
        info!(log, "    SET GATEWAY {}", gateway);

        /*
         * This attempts to add the default route to the live system.  It
         * may fail (e.g., if the route already exists) but we should just
         * report and ignore such a failure as long as we are able to write
         * the config file.
         */
        let output = Command::new("/usr/sbin/route")
            .env_clear()
            .arg("add")
            .arg("default")
            .arg(gateway)
            .output()?;

        if !output.status.success() {
            warn!(log, "route add failure: {}", output.info());
        }

        write_lines(log, DEFROUTER, defrouters)?;
    }

    Ok(())
}

fn ensure_ipv4_interface_dhcp(log: &Logger, sfx: &str, n: &str) -> Result<()> {
    info!(log, "ENSURE IPv4 DHCP INTERFACE: {}", n);

    ensure_ipadm_interface(log, &n)?;

    let targname = format!("{}/{}", n, sfx);
    info!(log, "target IP name: {}", targname);

    let addrs = ipadm_address_list()?;
    info!(log, "ADDRESSES: {:?}", &addrs);

    let mut name_found = false;
    let mut address_found = false;
    for addr in &addrs {
        if addr.name == targname {
            info!(log, "ipadm address with name exists: {:?}", addr);
            name_found = true;
        }
        if addr.type_ == "dhcp" {
            info!(log, "ipadm DHCP address exists: {:?}", addr);
            address_found = true;
        }
    }

    if name_found && !address_found {
        info!(
            log,
            "ipadm address exists but with wrong IP address, deleting"
        );
        let output = Command::new(IPADM)
            .env_clear()
            .arg("delete-addr")
            .arg(&targname)
            .output()?;

        if !output.status.success() {
            bail!("ipadm delete-addr {}: {}", &targname, output.info());
        }
    }

    if !address_found {
        info!(log, "ipadm DHCP address NEEDS CREATION");
        let output = Command::new(IPADM)
            .env_clear()
            .arg("create-addr")
            .arg("-T")
            .arg("dhcp")
            .arg("-1")
            .arg("-w")
            .arg("10")
            .arg(&targname)
            .output()?;

        if !output.status.success() {
            bail!("ipadm create-addr {} DHCP: {}", &targname, output.info());
        }
    }

    /*
     * Wait for the interface to be in the OK state:
     */
    loop {
        let list = ipadm_address_list()?;
        let addr = list.iter().find(|a| a.name == targname);

        info!(log, "address state: {:?}", addr);

        if let Some(addr) = addr {
            if addr.state == "ok" {
                info!(
                    log,
                    "ok, interface {} address {} ({}) complete", n, addr.cidr, sfx
                );
                return Ok(());
            }
        } else {
            bail!("address for {} not found?! {:#?}", targname, list);
        }

        info!(log, "waiting for DHCP...");
        sleep(5_000);
    }
}

fn ensure_ipv4_interface(
    log: &Logger,
    sfx: &str,
    mac_option: Option<&str>,
    link_name: Option<&str>,
    ipv4: &str,
) -> Result<()> {
    let found_nic = if let Some(mac) = mac_option {
        match mac_to_nic(mac)? {
            None => bail!("MAC address {} not found", mac),
            Some(n) => {
                info!(log, "MAC address {} is NIC {}", mac, n);
                n
            }
        }
    } else if let Some(name) = link_name {
        String::from(name)
    } else {
        panic!("programmer error: either link_name or mac_address must be passed to this function got none of both");
    };

    info!(log, "ENSURE IPv4 INTERFACE: {}, {:?}", found_nic, ipv4);

    ensure_ipadm_interface(log, &found_nic)?;

    info!(log, "target IP address: {}", ipv4);

    let targname = format!("{}/{}", found_nic, sfx);
    info!(log, "target IP name: {}", targname);

    let addrs = ipadm_address_list()?;
    info!(log, "ADDRESSES: {:?}", &addrs);

    let mut name_found = false;
    let mut address_found = false;
    for addr in &addrs {
        if addr.name == targname {
            info!(log, "ipadm address with name exists: {:?}", addr);
            name_found = true;
        }
        if addr.cidr == ipv4 {
            info!(log, "ipadm address with correct IP exists: {:?}", addr);
            address_found = true;
        }
    }

    if name_found && !address_found {
        info!(
            log,
            "ipadm address exists but with wrong IP address, deleting"
        );
        let output = Command::new(IPADM)
            .env_clear()
            .arg("delete-addr")
            .arg(&targname)
            .output()?;

        if !output.status.success() {
            bail!("ipadm delete-addr {}: {}", &targname, output.info());
        }
    }

    if !address_found {
        info!(log, "ipadm address {} NEEDS CREATION", ipv4);
        let output = Command::new(IPADM)
            .env_clear()
            .arg("create-addr")
            .arg("-T")
            .arg("static")
            .arg("-a")
            .arg(ipv4)
            .arg(&targname)
            .output()?;

        if !output.status.success() {
            bail!(
                "ipadm create-addr {} {}: {}",
                &targname,
                ipv4,
                output.info()
            );
        }
    }

    info!(
        log,
        "ok, interface {} address {} ({}) complete", found_nic, ipv4, sfx
    );
    Ok(())
}

fn main() {
    let log = init_log();

    match run(&log) {
        Ok(()) => {
            info!(log, "ok, run complete");
            std::process::exit(0);
        }
        Err(e) => {
            error!(log, "fatal error: {:?}", e);
            std::process::exit(1);
        }
    }
}

fn run(log: &Logger) -> Result<()> {
    /*
     * This program could be destructive if run in the wrong place.  Try to
     * ensure it has at least been installed as an SMF service:
     */
    if let Some(fmri) = std::env::var_os("SMF_FMRI") {
        info!(log, "SMF instance: {}", fmri.to_string_lossy());
    } else {
        bail!("SMF_FMRI is not set; running under SMF?");
    }

    ensure_dir(log, METADATA_DIR)?;

    /*
     * First, expand the ZFS pool.  We can do this prior to metadata access.
     */
    phase_expand_zpool(log)?;
    phase_add_swap(log)
        .map_err(|e| error!(log, "add swap failed: {}", e))
        .ok();

    /*
     * Try first to use SMBIOS information to determine what kind of hypervisor
     * this guest is running on:
     */
    if let Some(smbios) = smbios(log)? {
        info!(log, "SMBIOS information: {:?}", smbios);

        match (smbios.manufacturer.as_str(), smbios.product.as_str()) {
            ("Joyent", "SmartDC HVM") => {
                info!(log, "hypervisor type: SmartOS (from SMBIOS)");
                run_smartos(log)?;
                return Ok(());
            }
            ("DigitalOcean", "Droplet") => {
                info!(log, "hypervisor type: DigitalOcean (from SMBIOS)");
                run_digitalocean(log)?;
                return Ok(());
            }
            ("Xen", "HVM domU") => {
                if smbios.version.contains("amazon") {
                    info!(log, "hypervisor type: Amazon AWS Xen (from SMBIOS)");
                    run_amazon(log)?;
                    return Ok(());
                }
            }
            ("Amazon EC2", _) => {
                info!(log, "hypervisor type: Amazon AWS Nitro (from SMBIOS)");
                run_amazon(log)?;
                return Ok(());
            }
            ("OmniOS", "OmniOS HVM") | ("OpenIndiana", "OpenIndiana HVM") => {
                info!(log, "hypervisor type: illumos BHYVE (from SMBIOS)");
                run_illumos(log, &smbios.uuid)?;
                return Ok(());
            }
            ("QEMU", _) => {
                info!(log, "hypervisor type: Generic QEMU (from SMBIOS)");
                run_illumos(log, &smbios.uuid)?;
                return Ok(());
            }
            ("VMware, Inc.", "VMware Virtual Platform") => {
                info!(log, "hypervisor type: VMware (from SMBIOS)");
                run_generic(log, &smbios.uuid, true)?;
                return Ok(());
            }
            _ => {}
        }

        error!(log, "unrecognised SMBIOS information";
            "manufacturer" => smbios.manufacturer.as_str(),
            "product" => smbios.product.as_str(),
            "version" => smbios.version.as_str());
    } else {
        info!(log, "no SMBIOS data, looking for cpio device...");
        let dev = find_cpio_device(log)?;
        if let Some(dev) = dev {
            info!(log, "hypervisor type: Generic (no SMBIOS, cpio {})", dev);
            run_generic(log, "unknown", true)?;
            return Ok(());
        }
    }

    /*
     * If we could not guess based on the hypervisor, fall back to probing:
     */
    if mdata_probe(log)? {
        info!(log, "hypervisor type: SmartOS (mdata probe)");
        run_smartos(log)?;
        return Ok(());
    }

    /*
     * As a last level fallback, try the DigitalOcean mechanism:
     */
    info!(log, "hypervisor type: DigitalOcean (wild guess)");
    run_digitalocean(log)?;
    Ok(())
}

fn run_generic(log: &Logger, smbios_uuid: &str, network: bool) -> Result<()> {
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
            .arg(&dev)
            .current_dir(UNPACKDIR)
            .env_clear()
            .output()?;

        if !cpio.status.success() {
            bail!("cpio failure: {}", cpio.info());
        }

        info!(log, "ok, cpio extracted");
    }

    /*
     * Get a system hostname from the archive, if provided.  Make sure to set
     * this before engaging DHCP, so that "virsh net-dhcp-leases default" can
     * display the hostname in the lease record instead of "unknown".
     */
    let name = format!("{}/nodename", UNPACKDIR);
    if let Some(name) = read_file(&name)? {
        phase_set_hostname(log, &name.trim())?;
    }

    if network {
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
            chosen = ifaces.iter().next().map(|x| x.as_str());
        }

        if let Some(chosen) = chosen {
            info!(log, "chose interface {}", chosen);
            ensure_ipv4_interface_dhcp(log, "dhcp", chosen)?;
        } else {
            bail!("could not find an appropriate Ethernet interface!");
        }
    }

    /*
     * Get SSH public keys from the archive, if provided:
     */
    let keys = format!("{}/authorized_keys", UNPACKDIR);
    if let Some(keys) = read_lines(&keys)? {
        ensure_pubkeys(log, "root", keys.as_slice())?;
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

#[derive(Default)]
struct SMBIOSDatasource {
    uuid: String,
    datasource: String,
    seed_from: String,
    local_hostname: String,
}

fn parse_smbios_datasource_string(raw_string: &str) -> Result<SMBIOSDatasource> {
    let mut ds = SMBIOSDatasource::default();
    for part in raw_string.split(";") {
        let key_val: Vec<&str> = part.split("=").collect();
        match key_val[0] {
            "ds" => ds.datasource = String::from(key_val[1]),
            "i" | "instance-id" => ds.uuid = String::from(key_val[1]),
            "s" | "seedfrom" => ds.seed_from = String::from(key_val[1]),
            "h" | "local-hostname" => ds.local_hostname = String::from(key_val[1]),
            _ => {}
        }
    }

    Ok(ds)
}

fn ensure_network_config(
    log: &Logger,
    config: &userdata::networkconfig::NetworkConfig,
) -> Result<()> {
    let net_config = match config {
        userdata::networkconfig::NetworkConfig::V1(c) => &c.config,
        userdata::networkconfig::NetworkConfig::V2(_) => {
            error!(log, "Network config v2 not supported yet");
            bail!("Network Config v2 not supported");
        }
    };

    // First configure the Physical Interfaces
    for iface_config in net_config {
        match iface_config {
            NetworkDataV1Iface::Physical {
                name,
                mac_address: mac_address_option,
                mtu: mtu_option,
                subnets: subnet_option,
            } => {
                // First we make sure the Interface is named correctly
                // if we have a mac address set. Thus making
                // the optional mac address attribute the
                // attribute to identify the nic
                // not providing a mac address thus results in the name
                // being the identifying attribute
                if let Some(mac_addr) = mac_address_option {
                    info!(log, "ensuring nic with mac {} is named {}", mac_addr, name);
                    ensure_interface_name(log, name, &mac_addr)?;
                }

                if let Some(mtu) = mtu_option {
                    ensure_interface_mtu(log, name, mtu)?;
                }

                if let Some(subnets) = subnet_option {
                    ensure_ipadm_subnets_config(log, name, subnets)?;
                }
            }
            _ => {}
        }
    }

    // On the Second pass configure the combined ineterfaces (Bond, Bridge, VLAN...)
    for iface_config in net_config {
        match iface_config {
            NetworkDataV1Iface::Bond { .. } => {
                bail!("bonds not yet supported")
            }
            NetworkDataV1Iface::Bridge { .. } => {
                bail!("bridges not yet supported")
            }
            NetworkDataV1Iface::Vlan { .. } => {
                bail!("vlans not yet supported")
            }
            _ => {}
        }
    }

    //Configure Routes
    for iface_config in net_config {
        match iface_config {
            NetworkDataV1Iface::Route { .. } => {
                bail!("routes not yet supported")
            }
            _ => {}
        }
    }

    //Finaly configure nameservers
    for iface_config in net_config {
        match iface_config {
            NetworkDataV1Iface::Nameserver {
                address, search, ..
            } => {
                ensure_dns_nameservers(log, address)?;
                ensure_dns_search(log, search)?;
            }
            _ => {}
        }
    }

    Ok(())
}

fn run_illumos(log: &Logger, smbios_raw_string: &str) -> Result<()> {
    /*
     * Parse any datasource definition from smbios_uuid field, which by cloud-init standard is
     * not just the uuid
     */
    let ds = parse_smbios_datasource_string(smbios_raw_string)?;

    /*
     * Load our stamp file to see if the Guest UUID has changed.
     */
    if let Some([id]) = read_lines(STAMP)?.as_deref() {
        if id.trim() == ds.uuid {
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
                ds.uuid
            );
        }
    }

    phase_reguid_zpool(log)?;

    /*
     * The meta-data and user-data can be provided via a vfat (pcfs) or iso9660 (hsfs)
     *
     */
    info!(log, "searching for cidata device with metadata...");
    let devs_opt = find_cidata_devices(log)?;
    if let Some(devs) = devs_opt {
        if let Some(dev) = devs.first() {
            info!(log, "mounting cidata device {} to {}", dev.path, UNPACKDIR);
            ensure_dir(log, UNPACKDIR)?;
            let mount = Command::new(MOUNT)
                .arg("-F")
                .arg(&dev.fstype)
                .arg(&dev.path)
                .arg(UNPACKDIR)
                .env_clear()
                .output()?;

            if !mount.status.success() {
                bail!("mount failure: {}", mount.info());
            }

            info!(log, "ok, disk mounted");
        }
    } else {
        bail!("could not find a cidata device bailing")
    }

    let dir_buf = PathBuf::from(UNPACKDIR);

    let meta_data_file = File::open(&dir_buf.join("meta-data"))?;
    let meta_data =
        serde_yaml::from_reader::<File, userdata::cloudconfig::Metadata>(meta_data_file)?;

    /*
     * Get a system hostname from the metadata, if provided.  Make sure to set
     * this before engaging DHCP, so that "virsh net-dhcp-leases default" can
     * display the hostname in the lease record instead of "unknown".
     */
    phase_set_hostname(log, meta_data.get_hostname())?;

    let network_config_result =
        userdata::networkconfig::parse_network_config(&dir_buf.join("network-config"));
    // Apply network config if we have one.
    if network_config_result.is_ok() {
        ensure_network_config(&log, &network_config_result?)?;
    } else {
        /*
         * If we have no network config try DHCP.  Virtio interfaces are
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
            chosen = ifaces.iter().next().map(|x| x.as_str());
        }

        if let Some(chosen) = chosen {
            info!(log, "chose interface {}", chosen);
            ensure_ipv4_interface_dhcp(log, "dhcp", chosen)?;
        } else {
            bail!("could not find an appropriate Ethernet interface!");
        }
    }

    write_lines(log, STAMP, &[ds.uuid])?;

    Ok(())
}

fn run_amazon(log: &Logger) -> Result<()> {
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
        chosen = ifaces.iter().next().map(|x| x.as_str());
    }

    if let Some(chosen) = chosen {
        info!(log, "chose interface {}", chosen);
        ensure_ipv4_interface_dhcp(log, "dhcp", chosen)?;
    } else {
        bail!("could not find an appropriate Ethernet interface!");
    }

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
                instid
            );
        }
    }

    phase_reguid_zpool(log)?;

    /*
     * Determine the node name for this guest:
     */
    let (src, n) = if let Some(hostname) = dhcpinfo(log, "hostname")? {
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
        ensure_pubkeys(log, "root", &pubkeys)?;
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

fn run_smartos(log: &Logger) -> Result<()> {
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
                    error!(log, "interface {} requires {} support", nic.interface, ip);
                    continue;
                }

                let sfx = format!("ip{}", i);

                if let Err(e) = ensure_ipv4_interface(log, &sfx, Some(&nic.mac), None, &ip) {
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

        ensure_dns_nameservers(log, &resolvers)?;
    }

    /*
     * Get public keys:
     */
    if let Mdata::Found(pubkeys) = mdata_get(log, "root_authorized_keys")? {
        let pubkeys: Vec<String> = pubkeys.lines().map(|s| s.trim().to_string()).collect();

        ensure_pubkeys(log, "root", &pubkeys)?;
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

fn run_digitalocean(log: &Logger) -> Result<()> {
    /*
     * First, locate and mount the metadata ISO.  We need to load the droplet ID
     * so that we can determine if we have completed first boot processing for
     * this droplet or not.
     */
    let mounts = mounts()?;
    let mdmp: Vec<_> = mounts
        .iter()
        .filter(|m| m.mount_point == MOUNTPOINT)
        .collect();

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

        let dev = if let Some(dev) = find_device()? {
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
    let md: Option<DOMetadata> = read_json(&format!("{}/digitalocean_meta_data.json", MOUNTPOINT))?;

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

        if let Err(e) =
            ensure_ipv4_interface(log, "private", Some(&iface.mac), None, &iface.ipv4.cidr()?)
        {
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

        if let Err(e) =
            ensure_ipv4_interface(log, "public", Some(&iface.mac), None, &iface.ipv4.cidr()?)
        {
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
            if let Err(e) =
                ensure_ipv4_interface(log, "anchor", Some(&iface.mac), None, &anchor.cidr()?)
            {
                error!(log, "ANCHOR IFACE ERROR: {}", e);
            }
        }
    }

    ensure_dns_nameservers(log, &md.dns.nameservers)?;
    ensure_pubkeys(log, "root", md.public_keys.as_slice())?;

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

fn phase_reguid_zpool(log: &Logger) -> Result<()> {
    info!(log, "regenerate pool guid for rpool");
    zpool::zpool_reguid("rpool")?;
    Ok(())
}

fn phase_expand_zpool(log: &Logger) -> Result<()> {
    /*
     * NOTE: Though it might seem like we could skip directly to using "zpool
     * online -e ...", there appears to be at least one serious deadlock in this
     * code path.  The relabel operation appears to make the device briefly
     * unavailable at exactly the moment zpool(1M) then tries to reopen it,
     * which permanently corks access to the pool and hangs the machine.
     * Instead, we go the long way around and use format(1M) and fmthard(1M) to
     * effect our own expansion of the GPT and the slice first, so that
     * zpool(1M) can skip straight to reopening the device.
     */
    let disk = zpool::zpool_disk()?;
    info!(log, "rpool disk: {}", disk);

    if zpool::should_expand(&disk)? {
        info!(log, "expanding GPT...");
        zpool::format_expand(log, &disk)?;
        info!(log, "GPT expansion ok");
    }

    zpool::grow_data_partition(log, &disk)?;

    info!(log, "expanding zpool...");
    zpool::zpool_expand("rpool", &disk)?;
    info!(log, "zpool expansion ok");

    Ok(())
}

fn phase_add_swap(log: &Logger) -> Result<()> {
    /*
     * Next, add a swap device.  Ideally we will have enough room for a swap
     * file twice the size of physical memory -- but if not, we want to use at
     * most 20% of the available space in the pool.
     */
    let swapsize_from_pool = zpool::zpool_logical_size("rpool")? / 5;
    let swapsize = swapsize_from_pool.min(memsize()? * 2);

    let swapdev = "/dev/zvol/dsk/rpool/swap";
    if !exists_zvol("rpool/swap")? {
        info!(log, "create swap zvol...");
        create_zvol("rpool/swap", swapsize)?;
    } else {
        info!(log, "swap zvol exists");
    }

    let mut vfstab = read_lines("/etc/vfstab")?.unwrap();
    let mut found = false;
    for l in &vfstab {
        let t: Vec<_> = l.trim().split_whitespace().collect();
        if t.len() < 7 {
            continue;
        }

        if t[0] == swapdev {
            found = true;
        }
    }
    if !found {
        info!(log, "adding swap to vfstab");
        vfstab.push("".into());
        vfstab.push(format!("{}\t-\t-\tswap\t-\tno\t-", swapdev));
        write_lines(log, "/etc/vfstab", &vfstab)?;

        swapadd()?;
    } else {
        info!(log, "swap already configured in vfstab");
    }

    Ok(())
}

fn phase_set_hostname(log: &Logger, hostname: &str) -> Result<()> {
    /*
     * Check nodename:
     */
    let write_nodename = if let Some(nodename) = read_file("/etc/nodename")? {
        nodename.trim() != hostname
    } else {
        true
    };

    if write_nodename {
        info!(log, "WRITE NODENAME \"{}\"", hostname);

        let status = Command::new(HOSTNAME).env_clear().arg(hostname).status()?;

        if !status.success() {
            error!(log, "could not set live system hostname");
        }

        /*
         * Write the file after we set the live system hostname, so that if we
         * are restarted we don't forget to do that part.
         */
        write_lines(log, "/etc/nodename", &[hostname])?;
    } else {
        info!(log, "NODENAME \"{}\" OK ALREADY", hostname);
    }

    /*
     * Write /etc/hosts file with new nodename...
     */
    let hosts = read_lines("/etc/inet/hosts")?.unwrap();
    let hostsout: Vec<String> = hosts
        .iter()
        .map(|l| {
            /*
             * Split the line into a substantive portion and an optional comment.
             */
            let sect: Vec<&str> = l.splitn(2, '#').collect();

            let mut fore = sect[0].to_string();

            if !sect[0].trim().is_empty() {
                /*
                 * If the line has a substantive portion, split that into an IP
                 * address and a set of host names:
                 */
                let portions: Vec<&str> = sect[0].splitn(2, |c| c == ' ' || c == '\t').collect();

                if portions.len() > 1 {
                    /*
                     * Rewrite only the localhost entry, to include the system node
                     * name.  This essentially matches the OmniOS out-of-box file
                     * contents.
                     */
                    if portions[0] == "127.0.0.1" || portions[0] == "::1" {
                        let mut hosts = String::new();
                        hosts.push_str(portions[0]);
                        if portions[0] == "::1" {
                            hosts.push('\t');
                        }
                        hosts.push_str("\tlocalhost");
                        if portions[0] == "127.0.0.1" {
                            hosts.push_str(" loghost");
                        }
                        hosts.push_str(&format!(" {}.local {}", hostname, hostname));

                        fore = hosts;
                    }
                }
            }

            if sect.len() > 1 {
                format!("{}#{}", fore, sect[1])
            } else {
                fore
            }
        })
        .collect();
    write_lines(log, "/etc/inet/hosts", &hostsout)?;

    Ok(())
}

fn ensure_dns_nameservers(log: &Logger, nameservers: &[String]) -> Result<()> {
    /*
     * DNS Servers:
     */
    info!(log, "checking DNS configuration...");
    let lines = read_lines_maybe("/etc/resolv.conf")?;
    info!(log, "existing DNS config lines: {:#?}", &lines);

    let mut dirty = false;
    let mut file: Vec<String> = Vec::new();

    for ns in nameservers.iter() {
        let l = format!("nameserver {}", ns);
        if !lines.contains(&l) {
            info!(log, "ADD DNS CONFIG LINE: {}", l);
            file.push(l);
            dirty = true;
        }
    }

    for l in &lines {
        let ll: Vec<_> = l.splitn(2, ' ').collect();
        if ll.len() == 2 && ll[0] == "nameserver" && !nameservers.contains(&ll[1].to_string()) {
            info!(log, "REMOVE DNS CONFIG LINE: {}", l);
            file.push(format!("#{}", l));
            dirty = true;
        } else {
            file.push(l.to_string());
        }
    }

    if dirty {
        write_lines(log, "/etc/resolv.conf", file.as_ref())?;
    }

    Ok(())
}

fn ensure_dns_search(log: &Logger, dns_search: &[String]) -> Result<()> {
    /*
     * DNS Servers:
     */
    info!(log, "checking DNS search configuration...");
    let lines = read_lines_maybe("/etc/resolv.conf")?;
    info!(log, "existing DNS search config lines: {:#?}", &lines);

    let mut dirty = false;
    let mut file: Vec<String> = Vec::new();

    for ns in dns_search.iter() {
        let l = format!("search {}", ns);
        if !lines.contains(&l) {
            info!(log, "ADD DNS Search CONFIG LINE: {}", l);
            file.push(l);
            dirty = true;
        }
    }

    for l in &lines {
        let ll: Vec<_> = l.splitn(2, ' ').collect();
        if ll.len() == 2 && ll[0] == "search" && !dns_search.contains(&ll[1].to_string()) {
            info!(log, "REMOVE DNS Search CONFIG LINE: {}", l);
            file.push(format!("#{}", l));
            dirty = true;
        } else {
            file.push(l.to_string());
        }
    }

    if dirty {
        write_lines(log, "/etc/resolv.conf", file.as_ref())?;
    }

    Ok(())
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
