use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, bail, Result};
use serde::Deserialize;

use super::prelude::*;

pub fn probe(_log: &Logger) -> Result<bool> {
    Ok(find_device("pcfs", Some("cidata"))?.is_some())
}

pub fn run(log: &Logger, smbios_uuid: &str) -> Result<()> {
    /*
     * We need to mount the metadata volume before doing anything else, as it be
     * what provides us with the instance ID on this system.
     *
     * Check to see if the metadata file system is already mounted.
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
            if m.fstype != "pcfs" {
                bail!("INVALID MOUNTED FILE SYSTEM: {:#?}", m);
            }
            false
        }
        m => {
            bail!("found these mounts for {}: {:#?}", MOUNTPOINT, m);
        }
    };

    if do_mount {
        ensure_dir(log, MOUNTPOINT)?;

        /*
         * NoCloud metadata can appear on a device with a pcfs file system, with
         * the "cidata" volume label.
         */
        info!(log, "searching for pcfs device with NoCloud metadata...");
        let dev = if let Some(dev) = find_device("pcfs", Some("cidata"))? {
            dev
        } else {
            bail!("no pcfs file system found");
        };

        let output = Command::new(MOUNT)
            .env_clear()
            .arg("-F")
            .arg("pcfs")
            .arg("-o")
            .arg("ro")
            .arg(dev)
            .arg(MOUNTPOINT)
            .output()?;

        if !output.status.success() {
            bail!("mount: {}", output.info());
        }

        info!(log, "mount ok at {}", MOUNTPOINT);
    }

    /*
     * There are potentially several files in the device that interest us.  The
     * first is a file with per-instance metadata:
     */
    let mp = PathBuf::from(MOUNTPOINT);
    let md = match load_md(&mp.join("meta-data")) {
        Ok(Some(nc)) => {
            info!(log, "loaded meta-data from nocloud volume");
            Some(nc)
        }
        Ok(None) => {
            info!(log, "meta-data not found in nocloud volume");
            None
        }
        Err(e) => {
            error!(log, "meta-data load failed: {e}");
            None
        }
    };

    /*
     * The per-instance metadata may contain an instance ID that we can use to
     * identify this instance.  If not, fall back on whatever we gleaned from
     * SMBIOS (if anything!).
     */
    let instance_id = md
        .as_ref()
        .and_then(|md| md.instance_id.as_deref())
        .unwrap_or(smbios_uuid);

    /*
     * Load our stamp file to see if the Guest UUID has changed.
     */
    if let Some([id]) = read_lines(STAMP)?.as_deref() {
        if id.trim() == instance_id {
            /*
             * We may need to work around the off-network gateway issue each
             * boot, even if this is not a new instance:
             */
            workaround_offnet_gateway(log)?;

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
                instance_id,
            );
        }
    }

    phase_reguid_zpool(log)?;

    /*
     * Set the hostname and SSH keys if provided in the instance metadata:
     */
    if let Some(md) = &md {
        if let Some(name) = md.local_hostname.as_deref() {
            phase_set_hostname(log, name)?;
        }
        phase_pubkeys(log, &md.public_keys.as_slice())?;
    }

    /*
     * Next, process the network configuration:
     */
    let nc = match load_nc(&mp.join("network-config")) {
        Ok(Some(nc)) => {
            info!(log, "loaded network-config from nocloud volume");
            Some(nc)
        }
        Ok(None) => {
            info!(log, "network-config not found in nocloud volume");
            None
        }
        Err(e) => {
            error!(log, "network-config load failed: {e}");
            None
        }
    };

    if let Some(nc) = nc {
        for i in nc.interfaces(log)? {
            let nic = mac_to_nic(&i.mac)?
                .ok_or_else(|| anyhow!("MAC address {} not found", i.mac))?;

            match i.addr {
                InterfaceAddress::Static { addr, prefix } => {
                    if let Err(e) = ensure_ipv4_interface(
                        log,
                        &i.name,
                        &i.mac,
                        &format!("{addr}/{prefix}"),
                    ) {
                        error!(log, "IFACE ERROR: {e}");
                    };
                }
                InterfaceAddress::Dhcp => {
                    if let Err(e) =
                        ensure_ipv4_interface_dhcp(log, &i.name, &nic)
                    {
                        error!(log, "DHCP IFACE ERROR: {e}");
                    }
                }
            }
        }

        for gw in nc.gateways()? {
            ensure_ipv4_gateway(log, &gw.to_string())?;
        }

        phase_dns(
            log,
            /*
             * XXX really we should deal in IPv4 addresses across the board, not
             * strings; alas:
             */
            &nc.resolvers()?
                .into_iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
            &nc.domains()?,
        )?;
    } else {
        /*
         * If there is no provided network configuration, just try to set up
         * DHCP on the first NIC we find.
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
            warn!(log, "could not find an appropriate Ethernet interface!");
        }
    }

    workaround_offnet_gateway(log)?;

    /*
     * The last file of interest is the user-data file, which we will
     * treat as a user script for now.  In future we should also deal with
     * the #cloud-config format.
     */
    let udf = mp.join("user-data");
    let ud = load_ud(&udf)?;

    if let Some(ud) = ud.as_deref() {
        phase_userscript(log, ud)
            .map_err(|e| error!(log, "failed to get user-script: {}", e))
            .ok();
    }

    write_lines(log, STAMP, &[instance_id])?;

    Ok(())
}

fn workaround_offnet_gateway(log: &Logger) -> Result<()> {
    /*
     * First, check to see if we have obtained a single DHCP address.
     */
    let list = ipadm_address_list()?;
    let addr = list
        .iter()
        .filter(|a| a.type_ == "dhcp" && a.state == "ok")
        .collect::<Vec<_>>();

    let (nic, addr) = match addr.as_slice() {
        [] => return Ok(()),
        [a] => (a.name.split('/').next().unwrap().to_string(), a.cidr.clone()),
        other => bail!("too many DHCP interfaces: {other:?}"),
    };

    /*
     * Check to see if the address is for a /32 subnet, which means all
     * addresses (including the gateway address) are off-network:
     */
    let Some((addr, pfx)) = addr.split_once('/') else {
        return Ok(());
    };
    if pfx != "32" {
        return Ok(());
    }

    /*
     * Get the MAC address of the NIC so that we can check the vendor prefix:
     */
    let mac = nic_to_mac(&nic)?;
    if !mac.to_ascii_lowercase().starts_with("a8:40:25:") {
        /*
         * Ignore non-Oxide MAC OUI prefixes for now.
         */
        return Ok(());
    }

    /*
     * What was the gateway address we got from DHCP?
     */
    let Some(gw) = dhcpinfo(log, "Router")? else {
        return Ok(());
    };

    info!(log, "attempting to work around off-network gateway {gw}...");

    /*
     * Attempt to add an interface route for the gateway address:
     */
    let out = Command::new(ROUTE)
        .arg("add")
        .arg("-iface")
        .arg(format!("{gw}/32"))
        .arg(addr)
        .output()?;

    if !out.status.success() {
        warn!(log, "could not add gateway iface route: {}", out.info());
    }

    /*
     * The off-network gateway should now be reachable, so we can add the
     * default route:
     */
    let out = Command::new(ROUTE).arg("add").arg("default").arg(gw).output()?;

    if !out.status.success() {
        warn!(log, "could not add default gateway route: {}", out.info());
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct Interface {
    name: String,
    mac: String,
    addr: InterfaceAddress,
}

#[derive(Debug, PartialEq, Eq)]
enum InterfaceAddress {
    Static { addr: Ipv4Addr, prefix: u32 },
    Dhcp,
}

#[derive(Debug, PartialEq, Eq)]
pub enum NetworkConfig {
    V1(Network1),
}

impl NetworkConfig {
    fn interfaces(&self, log: &Logger) -> Result<Vec<Interface>> {
        match self {
            NetworkConfig::V1(nc) => {
                let cfgs = nc
                    .config
                    .iter()
                    .filter(|c| {
                        /*
                         * Look for physical interfaces where a MAC address has
                         * been specified.  Without a MAC address we cannot
                         * match this configuration to an interface on the
                         * system.
                         */
                        c.type_ == "physical" && c.mac_address.is_some()
                    })
                    .collect::<Vec<_>>();

                let mut out: Vec<Interface> = Default::default();
                let mut v4c = 0;
                for c in cfgs {
                    for s in c.subnets.iter() {
                        match s.type_.as_str() {
                            "dhcp" | "dhcp4" => {
                                if s.netmask.is_some()
                                    || s.address.is_some()
                                    || !s.dns_nameservers.is_empty()
                                    || !s.dns_search.is_empty()
                                {
                                    warn!(
                                        log,
                                        "ignoring overrides for DHCP \
                                        interface {:?}",
                                        c.name,
                                    );
                                }

                                let mac = c.mac_address.as_deref().unwrap();

                                out.push(Interface {
                                    name: "dhcp".to_string(),
                                    mac: mac.to_string(),
                                    addr: InterfaceAddress::Dhcp,
                                });
                            }
                            "static" => {
                                let nmp = s
                                    .netmask
                                    .as_deref()
                                    .map(|v| v.parse::<Ipv4Addr>())
                                    .transpose()?
                                    .and_then(|nm| {
                                        netmask_to_prefix_len(nm).ok()
                                    });

                                let Some(addr) = s.address.as_deref() else {
                                    warn!(
                                        log,
                                        "ignoring static interface {:?} \
                                        with no address",
                                        c.name
                                    );
                                    continue;
                                };

                                let (addr, p) = if let Some((a, p)) =
                                    addr.split_once('/')
                                {
                                    (
                                        a.parse::<Ipv4Addr>()?,
                                        Some(p.parse::<u32>()?),
                                    )
                                } else {
                                    (addr.parse::<Ipv4Addr>()?, None)
                                };

                                let prefix = if let Some((a, b)) = p.zip(nmp) {
                                    if a != b {
                                        bail!(
                                            "both netmask and prefix \
                                            length provided, but {a} != {b}"
                                        );
                                    }
                                    a
                                } else {
                                    p.or(nmp).unwrap()
                                };

                                out.push(Interface {
                                    name: if v4c == 0 {
                                        "v4".into()
                                    } else {
                                        format!("v4n{v4c}")
                                    },
                                    mac: c
                                        .mac_address
                                        .as_deref()
                                        .unwrap()
                                        .to_string(),
                                    addr: InterfaceAddress::Static {
                                        addr,
                                        prefix,
                                    },
                                });
                                v4c += 1;
                            }
                            _ => (),
                        }
                    }
                }

                Ok(out)
            }
        }
    }

    fn resolvers(&self) -> Result<Vec<Ipv4Addr>> {
        match self {
            NetworkConfig::V1(nc) => Ok(nc
                .config
                .iter()
                .flat_map(|c| {
                    c.subnets.iter().map(|s| s.dns_nameservers.clone())
                })
                .flatten()
                .collect::<Vec<_>>()
                .into_iter()
                .map(|ns| Ok(ns.parse::<Ipv4Addr>()?))
                .collect::<Result<Vec<_>>>()?),
        }
    }

    fn domains(&self) -> Result<Vec<String>> {
        match self {
            NetworkConfig::V1(nc) => Ok(nc
                .config
                .iter()
                .flat_map(|c| c.subnets.iter().map(|s| s.dns_search.clone()))
                .flatten()
                .collect::<Vec<_>>()),
        }
    }

    fn gateways(&self) -> Result<Vec<Ipv4Addr>> {
        match self {
            NetworkConfig::V1(nc) => Ok(nc
                .config
                .iter()
                .flat_map(|c| {
                    c.subnets.iter().filter_map(|s| s.gateway.as_deref())
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|ns| Ok(ns.parse::<Ipv4Addr>()?))
                .collect::<Result<Vec<_>>>()?),
        }
    }
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Network1 {
    version: u32,
    #[serde(default)]
    config: Vec<Config1>,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Config1 {
    #[serde(rename = "type")]
    type_: String,
    name: String,
    mac_address: Option<String>,
    mtu: Option<u32>,
    #[serde(default)]
    subnets: Vec<Subnet1>,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Subnet1 {
    #[serde(rename = "type")]
    type_: String,
    address: Option<String>,
    netmask: Option<String>,
    gateway: Option<String>,
    #[serde(default)]
    dns_nameservers: Vec<String>,
    #[serde(default)]
    dns_search: Vec<String>,
}

fn load_ud(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => bail!("reading {path:?}: {e}"),
    }
}

fn load_nc(path: &Path) -> Result<Option<NetworkConfig>> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            if s.is_empty() {
                /*
                 * At least propolis-standalone, if not also other hypervisors,
                 * provides an empty file (rather than eliding the file) if no
                 * network-config was configured.
                 */
                return Ok(None);
            }

            Ok(Some(parse_nc(&s)?))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => bail!("reading {path:?}: {e}"),
    }
}

fn parse_nc(input: &str) -> Result<NetworkConfig> {
    match serde_yaml::from_str::<Network1>(input) {
        Ok(nc) => {
            /*
             * If the version is not 1, we need to try a different parser even
             * if this one nominally appeared to succeed.
             */
            if nc.version == 1 {
                for c in &nc.config {
                    if c.type_ != "physical" {
                        bail!("unsupported network config type {:?}", c.type_);
                    }

                    for s in &c.subnets {
                        match s.type_.as_str() {
                            "dhcp" | "dhcp4" => (),
                            "static" => {
                                if let Some(a) = &s.address {
                                    if !a.contains('/') && s.netmask.is_none() {
                                        bail!(
                                            "must provide either a netmask \
                                            or a prefix length"
                                        );
                                    }
                                } else {
                                    bail!("static subnet without address");
                                }
                            }
                            other => bail!("unsupported subnet type {other:?}"),
                        }
                    }
                }

                return Ok(NetworkConfig::V1(nc));
            }
        }
        Err(e) => {
            bail!("parsing network config as V1: {e}");
        }
    }

    bail!("unrecognised network config");
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
struct MetaData {
    instance_id: Option<String>,
    local_hostname: Option<String>,
    #[serde(default)]
    public_keys: Vec<String>,
}

fn load_md(path: &Path) -> Result<Option<MetaData>> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            if s.is_empty() {
                /*
                 * At least propolis-standalone, if not also other hypervisors,
                 * provides an empty file (rather than eliding the file) if no
                 * meta-data was configured.
                 */
                return Ok(None);
            }

            Ok(Some(parse_md(&s)?))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => bail!("reading {path:?}: {e}"),
    }
}

fn parse_md(input: &str) -> Result<MetaData> {
    Ok(serde_json::from_str::<MetaData>(input)?)
}

#[cfg(test)]
mod test {
    use super::*;

    fn metadata0() -> (String, MetaData) {
        let input = format!(
            "{}\n",
            [
                "{\"instance-id\":\"ef245128-ed25-4dcd-9c47-94a1a439709b\",",
                "\"local-hostname\":\"helios-test\",",
                "\"public-keys\":[\"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABg",
                "nAYCRfaSW8n7JS5QAL9Uc1keTbGtsJjqoAEPxvc7a",
                "crpDmo+rMeoc+yDLPWLOSZPwfbDcIMftiyB/dxtYT",
                "JVLW0cwz0c9iYfGbNwztvObptcpHXI6hIpILOSUZF",
                "lA5kM45U4+AK+Tz0iFY045ycL373Ev0WqjBPyUUdE",
                "ZUtJ/rXAmLA5oxcfGQ8bPiFQVN8ncPeqBMxNkeihB",
                "vaJJ6dmg20YblsRAPgJNJhtmGngC4g6be5IHfuThj",
                "oSCBkp1bol/vXI6wDHcyLE= user@unixsystem\\n\"]}",
            ]
            .join("")
        );

        let output = MetaData {
            instance_id: Some("ef245128-ed25-4dcd-9c47-94a1a439709b".into()),
            local_hostname: Some("helios-test".into()),
            public_keys: vec!["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABg\
                nAYCRfaSW8n7JS5QAL9Uc1keTbGtsJjqoAEPxvc7a\
                crpDmo+rMeoc+yDLPWLOSZPwfbDcIMftiyB/dxtYT\
                JVLW0cwz0c9iYfGbNwztvObptcpHXI6hIpILOSUZF\
                lA5kM45U4+AK+Tz0iFY045ycL373Ev0WqjBPyUUdE\
                ZUtJ/rXAmLA5oxcfGQ8bPiFQVN8ncPeqBMxNkeihB\
                vaJJ6dmg20YblsRAPgJNJhtmGngC4g6be5IHfuThj\
                oSCBkp1bol/vXI6wDHcyLE= user@unixsystem\n"
                .into()],
        };

        (input, output)
    }

    fn netconf0() -> (String, NetworkConfig, Vec<Interface>) {
        let input = format!(
            "{}\n",
            [
                "version: 1",
                "config:",
                "  # Simple network adapter",
                "  - type: physical",
                "    name: interface0",
                "    mac_address: 00:11:22:33:44:55",
                "    subnets:",
                "      - type: static",
                "        address: 10.10.10.100/24",
                "        gateway: 10.10.10.1",
                "        dns_nameservers:",
                "          - 8.8.8.8",
                "          - 8.8.4.4",
                "        dns_search:",
                "          - example.com",
                "  # Second nic with Jumbo frames",
                "  - type: physical",
                "    name: jumbo0",
                "    mac_address: aa:11:22:33:44:55",
                "    subnets:",
                "      - type: dhcp",
                "    mtu: 9000",
                "  # 10G pair",
                "  - type: physical",
                "    name: gbe0",
                "    mac_address: cd:11:22:33:44:00",
                "  - type: physical",
                "    name: gbe1",
                "    mac_address: cd:11:22:33:44:02",
            ]
            .join("\n")
        );

        let output = NetworkConfig::V1(Network1 {
            version: 1,
            config: vec![
                Config1 {
                    type_: "physical".into(),
                    name: "interface0".into(),
                    mac_address: Some("00:11:22:33:44:55".into()),
                    mtu: None,
                    subnets: vec![Subnet1 {
                        type_: "static".into(),
                        address: Some("10.10.10.100/24".into()),
                        netmask: None,
                        gateway: Some("10.10.10.1".into()),
                        dns_nameservers: vec![
                            "8.8.8.8".into(),
                            "8.8.4.4".into(),
                        ],
                        dns_search: vec!["example.com".into()],
                    }],
                },
                Config1 {
                    type_: "physical".into(),
                    name: "jumbo0".into(),
                    mac_address: Some("aa:11:22:33:44:55".into()),
                    mtu: Some(9000),
                    subnets: vec![Subnet1 {
                        type_: "dhcp".into(),
                        address: None,
                        netmask: None,
                        gateway: None,
                        dns_nameservers: Default::default(),
                        dns_search: Default::default(),
                    }],
                },
                Config1 {
                    type_: "physical".into(),
                    name: "gbe0".into(),
                    mac_address: Some("cd:11:22:33:44:00".into()),
                    mtu: None,
                    subnets: Default::default(),
                },
                Config1 {
                    type_: "physical".into(),
                    name: "gbe1".into(),
                    mac_address: Some("cd:11:22:33:44:02".into()),
                    mtu: None,
                    subnets: Default::default(),
                },
            ],
        });

        let interfaces: Vec<Interface> = vec![
            Interface {
                name: "v4".into(),
                mac: "00:11:22:33:44:55".into(),
                addr: InterfaceAddress::Static {
                    addr: "10.10.10.100".parse().unwrap(),
                    prefix: 24,
                },
            },
            Interface {
                name: "dhcp".into(),
                mac: "aa:11:22:33:44:55".into(),
                addr: InterfaceAddress::Dhcp,
            },
        ];

        (input, output, interfaces)
    }

    #[test]
    fn parse_netconf0() -> Result<()> {
        let (input, output, _) = netconf0();
        let nc = parse_nc(&input)?;
        println!("{nc:#?}");
        assert_eq!(output, nc);
        Ok(())
    }

    #[test]
    fn make_abstract_interfaces_netconf0() -> Result<()> {
        let log = crate::common::init_log();
        let (input, _, interfaces) = netconf0();
        let nc = parse_nc(&input)?;
        let got = nc.interfaces(&log)?;
        println!("{got:#?}");
        assert_eq!(interfaces, got);
        Ok(())
    }

    #[test]
    fn parse_basic_metadata() -> Result<()> {
        let (input, output) = metadata0();
        let got = parse_md(&input)?;
        println!("{got:#?}");
        assert_eq!(output, got);
        Ok(())
    }
}
