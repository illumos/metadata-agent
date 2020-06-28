
use std::io::Read;
use std::io::Write;
use std::io::ErrorKind;
use std::collections::HashMap;
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::process::Command;

use serde::Deserialize;

use std::net::Ipv4Addr;

mod zpool;
mod common;
use common::*;


const MOUNTPOINT: &str = "/var/metadata";
const STAMP: &str = "/var/adm/digitalocean.stamp";


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

fn write_lines<L>(log: &Logger, p: &str, lines: &[L]) -> Result<()>
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

fn read_file(p: &str) -> Result<Option<String>> {
    let f = match std::fs::File::open(p) {
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

fn read_lines(p: &str) -> Result<Option<Vec<String>>> {
    Ok(read_file(p)?.map_or(None, |data| {
        Some(data.lines().map(|a| a.trim().to_string()).collect())
    }))
}

fn read_lines_maybe(p: &str) -> Result<Vec<String>> {
    Ok(match read_lines(p)? {
        None => Vec::new(),
        Some(l) => l,
    })
}

fn read_json<T>(p: &str) -> Result<Option<T>>
where for<'de> T: Deserialize<'de>
{
    let s = read_file(p)?;
    match s {
        None => Ok(None),
        Some(s) => Ok(serde_json::from_str(&s)?)
    }
}

#[derive(Debug)]
enum MountOptionValue {
    Present,
    Value(String),
}

#[derive(Debug)]
struct Mount {
    special: String,
    mount_point: String,
    fstype: String,
    options: HashMap<String, MountOptionValue>,
    time: u64,
}

#[derive(Debug,Deserialize)]
struct DNS {
    nameservers: Vec<String>,
}

#[derive(Debug,Deserialize)]
struct FloatingIP {
    active: bool,
}

#[derive(Debug,Deserialize)]
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

#[derive(Debug,Deserialize)]
struct Interface {
    anchor_ipv4: Option<IPv4>,
    ipv4: IPv4,
    mac: String,
    #[serde(rename = "type")]
    type_: String,
}

#[derive(Debug,Deserialize)]
struct Interfaces {
    public: Vec<Interface>,
    private: Vec<Interface>,
}

#[derive(Debug,Deserialize)]
struct Metadata {
    auth_key: String,
    dns: DNS,
    droplet_id: u64,
    floating_ip: FloatingIP,
    interfaces: Interfaces,
    hostname: String,
    public_keys: Vec<String>,
    region: String,
    features: HashMap<String, bool>,
}

/**
 * Read mnttab(4) and produce a list of mounts.  The result is a list instead of
 * a dictionary as there may be more than one mount entry for a particular mount
 * point.
 */
fn mounts() -> Result<Vec<Mount>> {
    let mnttab = read_lines("/etc/mnttab")?.unwrap();
    let rows: Vec<Vec<_>> = mnttab.iter()
        .map(|m| { m.split('\t').collect() })
        .collect();

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
            options: options,
            time: r[4].parse().expect("mnttab time value"),
        });
    }

    Ok(out)
}

fn exists_dir(p: &str) -> Result<bool> {
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

fn find_device() -> Result<Option<String>> {
    let i = std::fs::read_dir("/dev/dsk")?;

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

        /*
         * Determine which type of file system resides on the device:
         */
        let output = Command::new("/usr/sbin/fstyp")
            .env_clear()
            .arg(ent.path())
            .output()?;

        if !output.status.success() {
            continue;
        }

        if let Ok(s) = String::from_utf8(output.stdout) {
            if s.trim() == "hsfs" {
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

fn ipadm_interface_list() -> Result<Vec<String>> {
    let output = Command::new("/usr/sbin/ipadm")
        .env_clear()
        .arg("show-if")
        .arg("-p")
        .arg("-o").arg("ifname")
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

fn persistent_gateways() -> Result<Vec<String>> {
    let output = Command::new("/usr/sbin/route")
        .env_clear()
        .arg("-p")
        .arg("show")
        .output()?;

    if !output.status.success() {
        bail!("route failed: {:?}", output.stderr);
    }

    let stdout = String::from_utf8(output.stdout)?;
    let mut out = Vec::new();

    for l in stdout.lines() {
        let terms: Vec<&str> = l.split(' ').collect();
        match terms.as_slice() {
            ["persistent:", "route", "add", "default", gw] => {
                out.push(gw.to_string());
            }
            _ => continue,
        };
    }

    Ok(out)
}

fn ipadm_address_list() -> Result<Vec<IpadmAddress>> {
    let output = Command::new("/usr/sbin/ipadm")
        .env_clear()
        .arg("show-addr")
        .arg("-p")
        .arg("-o").arg("addrobj,type,state,addr")
        .output()?;

    if !output.status.success() {
        bail!("ipadm failed: {}", output.info());
    }

    let ents = parse_net_adm(output.stdout)?;

    Ok(ents.iter().map(|ent| IpadmAddress {
        name: ent[0].to_string(),
        type_: ent[1].to_string(),
        state: ent[2].to_string(),
        cidr: ent[3].to_string(),
    }).collect())
}

fn mac_sanitise(input: &str) -> String {
    let mac = input.split(':').fold(String::new(), |mut buf, octet| {
        if buf.len() > 0 {
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

fn mac_to_nic(mac: &str) -> Result<Option<String>> {
    let output = Command::new("/usr/sbin/dladm")
        .env_clear()
        .arg("show-phys")
        .arg("-m")
        .arg("-p")
        .arg("-o").arg("link,address")
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
    let output = std::process::Command::new("/usr/sbin/prtconf")
        .env_clear()
        .arg("-m")
        .output()?;

    if !output.status.success() {
        bail!("ipadm failed: {}", output.info());
    }

    Ok(String::from_utf8(output.stdout)?.trim().parse()?)
}

fn create_zvol(name: &str, size_mib: u64) -> Result<()> {
    let output = std::process::Command::new("/usr/sbin/zfs")
        .env_clear()
        .arg("create")
        .arg("-V").arg(format!("{}m", size_mib))
        .arg(name)
        .output()?;

    if !output.status.success() {
        bail!("zfs create failed: {}", output.info());
    }

    Ok(())
}

fn exists_zvol(name: &str) -> Result<bool> {
    let output = std::process::Command::new("/usr/sbin/zfs")
        .env_clear()
        .arg("list")
        .arg("-Hp")
        .arg("-o").arg("name,type")
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

    return Ok(false);
}

fn swapadd() -> Result<()> {
    let output = std::process::Command::new("/sbin/swapadd")
        .env_clear()
        .output()?;

    if !output.status.success() {
        bail!("swapadd failed: {}", output.info());
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
        let output = Command::new("/usr/sbin/ipadm")
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

fn ensure_ipv4_interface(log: &Logger, sfx: &str, mac: &str, ipv4: &IPv4,
    use_gw: bool) -> Result<()>
{
    info!(log, "ENSURE IPv4 INTERFACE: {}, {:?}, {}", mac, ipv4, use_gw);

    let n = match mac_to_nic(mac)? {
        None => bail!("MAC address {} not found", mac),
        Some(n) => n,
    };
    info!(log, "MAC address {} is NIC {}", mac, n);

    ensure_ipadm_interface(log, &n)?;

    let targ = ipv4.cidr()?;
    info!(log, "target IP address: {}", targ);

    let addrs = ipadm_address_list()?;
    info!(log, "ADDRESSES: {:?}", &addrs);

    let mut found = false;
    for addr in &addrs {
        if addr.cidr == targ {
            info!(log, "ipadm address exists: {:?}", addr);
            found = true;
        }
    }

    if !found {
        info!(log, "ipadm address {} NEEDS CREATION", &targ);
        let output = Command::new("/usr/sbin/ipadm")
            .env_clear()
            .arg("create-addr")
            .arg("-T").arg("static")
            .arg("-a").arg(&targ)
            .arg(format!("{}/{}", n, sfx))
            .output()?;

        if !output.status.success() {
            bail!("ipadm create-addr {} {}: {}", &targ, n, output.info());
        }
    }

    if use_gw {
        let gws = persistent_gateways()?;
        println!(" * GATEWAYS: {:?}", &gws);

        if !gws.contains(&ipv4.gateway) {
            println!("    ADD GATEWAY {}", &ipv4.gateway);
            let output = Command::new("/usr/sbin/route")
                .env_clear()
                .arg("-p")
                .arg("add")
                .arg("default")
                .arg(&ipv4.gateway)
                .output()?;

            if !output.status.success() {
                warn!(log, "route add failure: {}", output.info());
            }
        }
    }

    info!(log, "ok, interface {}  address {} ({}) complete", n, targ, sfx);
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
            error!(log, "fatal error: {}", e);
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

    /*
     * First, locate and mount the metadata ISO.  We need to load the droplet ID
     * so that we can determine if we have completed first boot processing for
     * this droplet or not.
     */
    let mounts = mounts()?;
    let mdmp: Vec<_> = mounts.iter()
        .filter(|m| { m.mount_point == MOUNTPOINT }).collect();

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

        if !exists_dir(MOUNTPOINT)? {
            info!(log, "should do mkdir");
            DirBuilder::new()
                .mode(0o700)
                .create(MOUNTPOINT)?;
        }

        let dev = if let Some(dev) = find_device()? {
            dev
        } else {
            bail!("no hsfs file system found");
        };

        let output = Command::new("/usr/sbin/mount")
            .env_clear()
            .arg("-F").arg("hsfs")
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
    let md: Option<Metadata> = read_json(
        &format!("{}/digitalocean_meta_data.json", MOUNTPOINT))?;

    let md = if let Some(md) = md {
        md
    } else {
        bail!("could not read metadata file");
    };

    info!(log, "metadata: {:#?}", md);

    /*
     * Load our stamp file to see if the Droplet ID has changed.
     */
    let sl = read_lines(STAMP)?;
    match sl.as_ref().map(|s| s.as_slice()) {
        Some([id]) => {
            let expected = md.droplet_id.to_string();

            if id.trim() == expected {
                info!(log, "this droplet has already completed first \
                    boot processing, halting");
                return Ok(());
            } else {
                info!(log, "droplet ID changed ({} -> {}), reprocessing",
                    id.trim(), expected);
            }
        }
        _ => (),
    }

    /*
     * First, expand the ZFS pool.  We can do this prior to metadata access.
     *
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

    /*
     * Next, add a swap device.
     */
    let swapdev = "/dev/zvol/dsk/rpool/swap";
    let swapsize = memsize()? * 2;
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

    /*
     * Check nodename:
     */
    let write_nodename = if let Some(nodename) = read_file("/etc/nodename")? {
        nodename.trim() != md.hostname
    } else {
        true
    };

    if write_nodename {
        info!(log, "WRITE NODENAME \"{}\"", &md.hostname);

        let status = Command::new("/usr/bin/hostname")
            .env_clear()
            .arg(&md.hostname)
            .status()?;

        if !status.success() {
             error!(log, "could not set live system hostname");
        }

        /*
         * Write the file after we set the live system hostname, so that if we
         * are restarted we don't forget to do that part.
         */
        write_lines(log, "/etc/nodename", &[ &md.hostname ])?;

    } else {
        info!(log, "NODENAME \"{}\" OK ALREADY", &md.hostname);
    }

    /*
     * Write /etc/hosts file with new nodename...
     */
    let hosts = read_lines("/etc/inet/hosts")?.unwrap();
    let hostsout: Vec<String> = hosts.iter().map(|l| {
        /*
         * Split the line into a substantive portion and an optional comment.
         */
        let sect: Vec<&str> = l.splitn(2, '#').collect();

        let mut fore = sect[0].to_string();

        if sect[0].trim().len() > 0 {
            /*
             * If the line has a substantive portion, split that into an IP
             * address and a set of host names:
             */
            let portions: Vec<&str> = sect[0]
                .splitn(2, |c| c == ' ' || c == '\t')
                .collect();

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
                    hosts.push_str(&format!(" {}.local {}",
                        &md.hostname, &md.hostname));

                    fore = hosts;
                }
            }
        }

        if sect.len() > 1 {
            format!("{}#{}", fore, sect[1])
        } else {
            format!("{}", fore)
        }
    }).collect();
    write_lines(log, "/etc/inet/hosts", &hostsout)?;

    /*
     * Check network configuration:
     */
    for iface in &md.interfaces.private {
        if iface.type_ != "private" {
            continue;
        }

        if let Err(e) = ensure_ipv4_interface(log, "private", &iface.mac,
            &iface.ipv4, false)
        {
            /*
             * Report the error, but drive on in case we can complete other
             * configuration and make the guest accessible anyway.
             */
            error!(log, "PRIV IFACE ERROR: {}", e);
        }
    }

    for iface in &md.interfaces.public {
        if iface.type_ != "public" {
            continue;
        }

        if let Err(e) = ensure_ipv4_interface(log, "public", &iface.mac,
            &iface.ipv4, true)
        {
            /*
             * Report the error, but drive on in case we can complete other
             * configuration and make the guest accessible anyway.
             */
            error!(log, "PUB IFACE ERROR: {}", e);
        }

        if let Some(anchor) = &iface.anchor_ipv4 {
            if let Err(e) = ensure_ipv4_interface(log, "anchor", &iface.mac,
                &anchor, false)
            {
                error!(log, "ANCHOR IFACE ERROR: {}", e);
            }
        }
    }

    /*
     * DNS Servers:
     */
    info!(log, "checking DNS configuration...");
    let lines = read_lines_maybe("/etc/resolv.conf")?;
    info!(log, "existing DNS config lines: {:#?}", &lines);

    let mut dirty = false;
    let mut file: Vec<String> = Vec::new();

    for ns in &md.dns.nameservers {
        let l = format!("nameserver {}", ns);
        if !lines.contains(&l) {
            info!(log, "ADD DNS CONFIG LINE: {}", l);
            file.push(l);
            dirty = true;
        }
    }

    for l in &lines {
        let ll: Vec<_> = l.splitn(2, ' ').collect();
        if ll.len() == 2 && ll[0] == "nameserver" &&
            !md.dns.nameservers.contains(&ll[1].to_string())
        {
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

    /*
     * Manage the public keys:
     */
    info!(log, "checking SSH public keys...");
    let mut file = read_lines_maybe("/root/.ssh/authorized_keys")?;
    info!(log, "existing SSH public keys: {:#?}", &file);

    let mut dirty = false;
    for key in &md.public_keys {
        if !file.contains(key) {
            info!(log, "add SSH public key: {}", key);
            file.push(key.to_string());
            dirty = true;
        }
    }

    if dirty {
        write_lines(log, "/root/.ssh/authorized_keys", file.as_ref())?;
    }

    write_lines(log, STAMP, &[md.droplet_id.to_string()])?;

    Ok(())
}
