
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


const MOUNTPOINT: &str = "/var/metadata";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;


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

fn write_lines<T: AsRef<str>>(p: &str, lines: &[T]) -> Result<()> {
    let mut out = String::new();
    println!("----- WRITE FILE: {} ----------------------", p);
    for l in lines {
        println!("| {}", l.as_ref());
        out.push_str(l.as_ref());
        out.push_str("\n");
    }
    println!("--------------------------------");
    println!("");
    write_file(p, &out)
}

fn read_file(p: &str) -> Result<Option<String>> {
    let f = match std::fs::File::open(p) {
        Ok(f) => f,
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::NotFound => return Ok(None),
                _ => return Err(format!("open \"{}\": {}", p, e).into()),
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
            return Err(format!("bits not left packed in {}",
                self.netmask).into());
        }

        let len = bits.count_ones();
        if bits.trailing_zeros() != 32 - len {
            return Err(format!("bits not contiguous in {}",
                self.netmask).into());
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
            _ => return Err(e.into()),
        },
    };

    if md.is_dir() {
        Ok(true)
    } else {
        Err(format!("\"{}\" exists but is not a directory", p).into())
    }
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
        n => Err(format!("found {} hsfs file systems", n).into()),
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
        return Err(format!("ipadm failed: {:?}", output.stderr).into());
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
        return Err(format!("route failed: {:?}", output.stderr).into());
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
        return Err(format!("ipadm failed: {:?}", output.stderr).into());
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
        return Err(format!("dladm failed: {:?}", output.stderr).into());
    }

    let mut nics: HashMap<String, &str> = HashMap::new();

    let ents = parse_net_adm(output.stdout)?;
    for ent in ents.iter() {
        let mac = mac_sanitise(&ent[1]);
        println!("MAC: {}", &mac);

        if nics.contains_key(mac.as_str()) {
            return Err(format!("MAC {} appeared on two NICs", &mac).into());
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
        return Err(format!("ipadm failed: {:?}", output.stderr).into());
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
        return Err(format!("zfs create failed: {:?}", output.stderr).into());
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
        return Err(format!("zfs list failed: {:?}", output.stderr).into());
    }

    let out = String::from_utf8(output.stdout)?;
    for l in out.lines() {
        let t: Vec<_> = l.split('\t').collect();
        assert_eq!(t.len(), 2);

        if t[0] != name {
            continue;
        }

        if t[1] != "volume" {
            return Err(format!("dataset {} was of type {}, not volume",
                name, t[1]).into());
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
        return Err(format!("swapadd failed: {:?}", output.stderr).into());
    }

    Ok(())
}

fn ensure_ipadm_interface(n: &str) -> Result<bool> {
    println!("    ENSURE INTERFACE: {}", n);

    let ifaces = ipadm_interface_list()?;
    println!(" * INTERFACES: {:?}", &ifaces);

    if ifaces.contains(&n.to_string()) {
        println!("        interface {} exists", n);
        Ok(false)
    } else {
        println!("        interface {} NEEDS CREATION", n);
        let output = Command::new("/usr/sbin/ipadm")
            .env_clear()
            .arg("create-if")
            .arg(n)
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            Err(format!("ERROR: ipadm create-if {}: {}", &n, err).into())
        } else {
            Ok(true)
        }
    }
}

fn ensure_ipv4_interface(sfx: &str, mac: &str, ipv4: &IPv4, use_gw: bool)
    -> Result<()>
{
    println!("    ENSURE IPv4 INTERFACE: {}, {:?}, {}", mac, ipv4, use_gw);

    println!("    find mac {}", mac);
    let n = match mac_to_nic(mac)? {
        None => {
            eprintln!("MAC {} not found", mac);
            std::process::exit(5);
        }
        Some(n) => n,
    };
    println!("        --> {:?}", n);

    ensure_ipadm_interface(&n)?;

    let targ = ipv4.cidr()?;
    println!("    target IP: {}", targ);

    let addrs = ipadm_address_list()?;
    println!(" * ADDRESSES: {:?}", &addrs);

    let mut found = false;
    for addr in &addrs {
        if addr.cidr == targ {
            println!("    ipadm address exists: {:?}", addr);
            found = true;
        }
    }

    if !found {
        println!("    ipadm address {} NEEDS CREATION", &targ);
        let output = Command::new("/usr/sbin/ipadm")
            .env_clear()
            .arg("create-addr")
            .arg("-T").arg("static")
            .arg("-a").arg(&targ)
            .arg(format!("{}/{}", n, sfx))
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!("ipadm create-addr {} {}: {}", &targ,
                n, err).into());
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
                let err = String::from_utf8_lossy(&output.stderr);
                return Err(format!("route add: {}", err).into());
            }
        }
    }

    println!("    ok, interface {}  address {} ({}) complete", n, targ, sfx);
    Ok(())
}

fn main() -> Result<()> {
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
    println!("rpool disk: {}", disk);

    if zpool::should_expand(&disk)? {
        println!("expanding GPT...");
        zpool::format_expand(&disk)?;
        println!("    ok");
    }

    zpool::grow_data_partition(&disk)?;

    println!("expanding zpool...");
    zpool::zpool_expand("rpool", &disk)?;
    println!("    ok");

    /*
     * Next, add a swap device.
     */
    let swapdev = "/dev/zvol/dsk/rpool/swap";
    let swapsize = memsize()? * 2;
    if !exists_zvol("rpool/swap")? {
        println!("create swap zvol...");
        create_zvol("rpool/swap", swapsize)?;
    } else {
        println!("swap zvol exists");
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
        println!("adding swap to vfstab");
        vfstab.push("".into());
        vfstab.push(format!("{}\t-\t-\tswap\t-\tno\t-", swapdev));
        write_lines("/etc/vfstab", &vfstab)?;

        swapadd()?;
    } else {
        println!("swap already configured in vfstab");
    }

    /*
     * Check to see if the Metadata ISO is mounted already:
     */
    let mounts = mounts()?;
    let mdmp: Vec<_> = mounts.iter()
        .filter(|m| { m.mount_point == MOUNTPOINT }).collect();

    let do_mount = match mdmp.len() {
        0 => true,
        1 => {
            /*
             * Check the existing mount to see if it is adequate.
             */
            let m = &mdmp[0];
            if m.fstype != "hsfs" {
                eprintln!("INVALID MOUNTED FILE SYSTEM: {:#?}", m);
                std::process::exit(10);
            }
            false
        }
        _ => {
            eprintln!("ERROR: found {} mounts for {}", mdmp.len(),
                MOUNTPOINT);
            std::process::exit(1);
        }
    };

    if do_mount {
        println!("should do mount");

        if !exists_dir(MOUNTPOINT)? {
            println!("should do mkdir");
            DirBuilder::new()
                .mode(0o700)
                .create(MOUNTPOINT)?;
        }

        let dev = match find_device()? {
            Some(dev) => dev,
            None => {
                eprintln!("ERROR: no hsfs file system found");
                std::process::exit(2);
            }
        };

        let output = Command::new("/usr/sbin/mount")
            .env_clear()
            .arg("-F").arg("hsfs")
            .arg(dev)
            .arg(MOUNTPOINT)
            .output()?;

        if !output.status.success() {
            eprintln!("ERROR: mount: {:?}", output.stderr);
            std::process::exit(3);
        }

        println!("mount ok");
    }

    /*
     * Read metadata from the file system:
     */
    let md: Option<Metadata> = read_json(
        &format!("{}/digitalocean_meta_data.json", MOUNTPOINT))?;

    let md = match md {
        Some(md) => md,
        None => {
            eprintln!("ERROR: could not read metadata file");
            std::process::exit(3);
        }
    };

    println!("metadata: {:#?}", md);

    /*
     * Check nodename:
     */
    let write_nodename = if let Some(nodename) = read_file("/etc/nodename")? {
        nodename.trim() != md.hostname
    } else {
        true
    };

    if write_nodename {
        println!("WRITE NODENAME \"{}\"", &md.hostname);

        let status = Command::new("/usr/bin/hostname")
            .env_clear()
            .arg(&md.hostname)
            .status()?;

        if !status.success() {
            eprintln!("WARNING: could not set live system hostname");
        }

        /*
         * Write the file after we set the live system hostname, so that if we
         * are restarted we don't forget to do that part.
         */
        write_lines("/etc/nodename", &[ &md.hostname ])?;

    } else {
        println!("NODENAME \"{}\" OK ALREADY", &md.hostname);
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
    write_lines("/etc/inet/hosts", &hostsout)?;

    /*
     * Check network configuration:
     */
    for iface in &md.interfaces.private {
        if iface.type_ != "private" {
            continue;
        }

        if let Err(e) = ensure_ipv4_interface("private", &iface.mac,
            &iface.ipv4, false)
        {
            /*
             * Report the error, but drive on in case we can complete other
             * configuration and make the guest accessible anyway.
             */
            println!("PRIV IFACE ERROR: {}", e);
        }
    }

    for iface in &md.interfaces.public {
        if iface.type_ != "public" {
            continue;
        }

        if let Err(e) = ensure_ipv4_interface("public", &iface.mac,
            &iface.ipv4, true)
        {
            /*
             * Report the error, but drive on in case we can complete other
             * configuration and make the guest accessible anyway.
             */
            println!("PUB IFACE ERROR: {}", e);
        }

        if let Some(anchor) = &iface.anchor_ipv4 {
            if let Err(e) = ensure_ipv4_interface("anchor", &iface.mac,
                &anchor, false)
            {
                println!("ANCHOR IFACE ERROR: {}", e);
            }
        }
    }

    /*
     * DNS Servers:
     */
    println!("checking DNS configuration...");
    let lines = if let Some(lines) = read_lines("/etc/resolv.conf")? {
        lines
    } else {
        Vec::new()
    };
    println!("existing lines: {:#?}", &lines);

    let mut dirty = false;
    let mut file: Vec<String> = Vec::new();

    for ns in &md.dns.nameservers {
        let l = format!("nameserver {}", ns);
        if !lines.contains(&l) {
            println!("ADD LINE: {}", l);
            file.push(l);
            dirty = true;
        }
    }

    for l in &lines {
        let ll: Vec<_> = l.splitn(2, ' ').collect();
        if ll.len() == 2 && ll[0] == "nameserver" &&
            !md.dns.nameservers.contains(&ll[1].to_string())
        {
            println!("REMOVE LINE: {}", l);
            file.push(format!("#{}", l));
            dirty = true;
        } else {
            file.push(l.to_string());
        }
    }

    if dirty {
        write_lines("/etc/resolv.conf", file.as_ref())?;
    }

    /*
     * Manage the public keys:
     */
    println!("checking public keys...");
    let mut file = if let Some(lines) = read_lines(
        "/root/.ssh/authorized_keys")?
    {
        lines
    } else {
        Vec::new()
    };
    println!("existing: {:#?}", &file);

    let mut dirty = false;
    for key in &md.public_keys {
        if !file.contains(key) {
            println!("add key: {}", key);
            file.push(key.to_string());
            dirty = true;
        }
    }

    if dirty {
        write_lines("/root/.ssh/authorized_keys", file.as_ref())?;
    }

    Ok(())
}
