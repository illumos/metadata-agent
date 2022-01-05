use std::fs::File;
use std::path::PathBuf;
use std::collections::HashMap;
use serde::{Deserialize};
use crate::userdata::multiformat_deserialize::Multiformat;

pub fn parse_network_config(path: &PathBuf) -> Result<NetworkConfig, failure::Error> {
    // Try V1 first
    let file = File::open(path)?;
    let f = serde_yaml::from_reader::<File, NetworkConfigFile>(file)?;
    Ok(f.network)
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct NetworkConfigFile {
    pub network: NetworkConfig,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "version")]
pub enum NetworkConfig {
    #[serde(rename = "1")]
    V1(NetworkDataV1),
    #[serde(rename = "2")]
    V2(NetworkDataV2)
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct NetworkDataV1 {
    pub config: Vec<NetworkDataV1Iface>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "type")]
pub enum NetworkDataV1Iface {
    #[serde(rename = "physical")]
    Physical { name: String, mac_address: Option<String>, mtu: Option<i32>, subnets: Option<Vec<NetworkDataV1Subnet>> },
    #[serde(rename = "bond")]
    Bond { name: String, mac_address: Option<String>, bond_interfaces: Vec<String>, mtu: Option<i32>, params: HashMap<String,String>, subnets: Option<Vec<NetworkDataV1Subnet>> },
    #[serde(rename = "bridge")]
    Bridge { name: String, bridge_interfaces: Vec<String>, params: HashMap<String, Multiformat>, subnets: Option<Vec<NetworkDataV1Subnet>> },
    #[serde(rename = "vlan")]
    Vlan { name: String, vlan_link: String, vlan_id: i32, mtu: Option<i32>, subnets: Option<Vec<NetworkDataV1Subnet>> },
    #[serde(rename = "nameserver")]
    Nameserver { address: Vec<String>, search: Vec<String>, interface: Option<String> },
    #[serde(rename = "route")]
    Route { destination: String, gateway: String, metric: i32 }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "type")]
pub enum NetworkDataV1Subnet {
    #[serde(rename = "dhcp4")]
    Dhcp4,
    #[serde(rename = "dhcp")]
    Dhcp,
    #[serde(rename = "dhcp6")]
    Dhcp6,
    #[serde(rename = "static")]
    Static(StaticSubnetConfig),
    #[serde(rename = "static6")]
    Static6(StaticSubnetConfig),
    #[serde(rename = "ipv6_dhcpv6-stateful")]
    Dhcpv6Stateful,
    #[serde(rename = "ipv6_dhcpv6-stateless")]
    Dhcpv6Stateless,
    #[serde(rename = "ipv6_slaac")]
    SLAAC { control: Option<NetworkDataV1SubnetControl>, gateway: String, dns_nameservers: Vec<String>, dns_search: Vec<String>, routes: Vec<NetworkDataV1SubnetRoute> }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct StaticSubnetConfig {
    pub address: String,
    pub gateway: Option<String>,
    pub netmask: Option<String>,
    pub control: Option<NetworkDataV1SubnetControl>,
    pub dns_nameservers: Option<Vec<String>>,
    pub dns_search: Option<Vec<String>>,
    pub routes: Option<Vec<NetworkDataV1SubnetRoute>>
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub enum NetworkDataV1SubnetControl {
    #[serde(rename = "manual")]
    Manual,
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "hotplug")]
    Hotplug
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct NetworkDataV1SubnetRoute {
    pub gateway: String,
    pub netmask: String,
    pub network: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct NetworkDataV2 {

}

#[cfg(test)]
mod tests {
    use crate::userdata::networkconfig::{parse_network_config, NetworkConfig, NetworkDataV1Iface, NetworkDataV1Subnet};
    use std::path::PathBuf;
    use std::str::FromStr;
    use crate::userdata::multiformat_deserialize::Multiformat;

    #[test]
    fn parse_physical () -> Result<(), failure::Error> {
        let cfg = parse_network_config(&PathBuf::from_str("./sample_data/network_config_v1/test_physical.yaml")?)?;
        match cfg {
            NetworkConfig::V1(v1) => {
                for iface in v1.config {
                    match iface {
                        NetworkDataV1Iface::Physical { name, .. } => {
                            assert_eq!(&name, "eth0");
                        }
                        _ => {
                            panic!("expected physical network config")
                        }
                    }
                }
            }
            NetworkConfig::V2(_) => {
                panic!("expected v1 config got v2")
            }
        }
        Ok(())
    }

    #[test]
    fn parse_physical_2 () -> Result<(), failure::Error> {
        let cfg = parse_network_config(&PathBuf::from_str("./sample_data/network_config_v1/test_physical_2.yaml")?)?;
        match cfg {
            NetworkConfig::V1(v1) => {
                match &v1.config[0] {
                    NetworkDataV1Iface::Physical { name, mac_address, .. } => {
                        assert_eq!(name.as_str(), "interface0");
                        assert_eq!(mac_address, &Some("00:11:22:33:44:55".to_owned()));
                    }
                    _ => {
                        panic!("expected physical network config")
                    }
                }
                match &v1.config[1] {
                    NetworkDataV1Iface::Physical { name, mac_address, mtu, .. } => {
                        assert_eq!(name.as_str(), "jumbo0");
                        assert_eq!(mac_address, &Some("aa:11:22:33:44:55".to_owned()));
                        assert_eq!(mtu, &Some(9000));
                    }
                    _ => {
                        panic!("expected physical network config")
                    }
                }
            }
            NetworkConfig::V2(_) => {
                panic!("expected v1 config got v2")
            }
        }
        Ok(())
    }

    #[test]
    fn parse_bond () -> Result<(), failure::Error> {
        let cfg = parse_network_config(&PathBuf::from_str("./sample_data/network_config_v1/test_bond.yaml")?)?;
        match cfg {
            NetworkConfig::V1(v1) => {
                match &v1.config[0] {
                    NetworkDataV1Iface::Physical { name, mac_address, .. } => {
                        assert_eq!(name.as_str(), "interface0");
                        assert_eq!(mac_address, &Some("00:11:22:33:44:55".to_owned()));
                    }
                    _ => {
                        panic!("expected physical network config")
                    }
                }
                match &v1.config[3] {
                    NetworkDataV1Iface::Bond { name, bond_interfaces, params, .. } => {
                        assert_eq!(name.as_str(), "bond0");
                        assert_eq!(bond_interfaces[0].as_str(), "gbe0");
                        assert_eq!(bond_interfaces[1].as_str(), "gbe1");
                        assert_eq!(params["bond-mode"].as_str(), "active-backup");
                    }
                    _ => {
                        panic!("expected physical network config")
                    }
                }
            }
            NetworkConfig::V2(_) => {
                panic!("expected v1 config got v2")
            }
        }
        Ok(())
    }

    #[test]
    fn parse_bridge () -> Result<(), failure::Error> {
        let cfg = parse_network_config(&PathBuf::from_str("./sample_data/network_config_v1/test_bridge.yaml")?)?;
        match cfg {
            NetworkConfig::V1(v1) => {
                match &v1.config[0] {
                    NetworkDataV1Iface::Physical { name, mac_address, .. } => {
                        assert_eq!(name.as_str(), "interface0");
                        assert_eq!(mac_address, &Some("00:11:22:33:44:55".to_owned()));
                    }
                    _ => {
                        panic!("expected physical network config")
                    }
                }
                match &v1.config[2] {
                    NetworkDataV1Iface::Bridge { name, bridge_interfaces, params, .. } => {
                        assert_eq!(name.as_str(), "br0");
                        assert_eq!(bridge_interfaces[0].as_str(), "jumbo0");
                        assert_eq!(params["bridge_ageing"], Multiformat::Integer(250));
                        assert_eq!(params["bridge_pathcost"], Multiformat::List(["jumbo0 75".to_owned()].to_vec()));
                    }
                    _ => {
                        panic!("expected physical network config")
                    }
                }
            }
            NetworkConfig::V2(_) => {
                panic!("expected v1 config got v2")
            }
        }
        Ok(())
    }

    #[test]
    fn parse_vlan () -> Result<(), failure::Error> {
        let cfg = parse_network_config(&PathBuf::from_str("./sample_data/network_config_v1/test_vlan.yaml")?)?;
        match cfg {
            NetworkConfig::V1(v1) => {
                match &v1.config[0] {
                    NetworkDataV1Iface::Physical { name, mac_address, .. } => {
                        assert_eq!(name.as_str(), "eth0");
                        assert_eq!(mac_address, &Some("c0:d6:9f:2c:e8:80".to_owned()));
                    }
                    _ => {
                        panic!("expected physical network config")
                    }
                }
                match &v1.config[1] {
                    NetworkDataV1Iface::Vlan { name, vlan_link, vlan_id, mtu, .. } => {
                        assert_eq!(name.as_str(), "eth0.101");
                        assert_eq!(vlan_link.as_str(), "eth0");
                        assert_eq!(vlan_id, &101);
                        assert_eq!(mtu, &Some(1500));
                    }
                    not => {
                        panic!("expected vlan network config, got {:?}", not)
                    }
                }
            }
            NetworkConfig::V2(_) => {
                panic!("expected v1 config got v2")
            }
        }
        Ok(())
    }

    #[test]
    fn parse_nameserver () -> Result<(), failure::Error> {
        let cfg = parse_network_config(&PathBuf::from_str("./sample_data/network_config_v1/test_nameserver.yaml")?)?;
        match cfg {
            NetworkConfig::V1(v1) => {
                match &v1.config[0] {
                    NetworkDataV1Iface::Physical { name, mac_address, subnets, .. } => {
                        assert_eq!(name.as_str(), "interface0");
                        assert_eq!(mac_address, &Some("00:11:22:33:44:55".to_owned()));
                        match subnets {
                            None => {
                                panic!("expected a subnet config in physical network config, got {:?}", subnets)
                            }
                            Some(nets) => {
                                let s0 = &nets[0];
                                match s0 {
                                    NetworkDataV1Subnet::Static(cfg) => {
                                        assert_eq!(cfg.address.as_str(), "192.168.23.14/27");
                                        assert_eq!(cfg.gateway, Some("192.168.23.1".to_owned()));
                                    }
                                    not => {
                                        panic!("expected static subnet config, got {:?}", not)
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        panic!("expected physical network config")
                    }
                }
                match &v1.config[1] {
                    NetworkDataV1Iface::Nameserver { address, search, interface } => {
                        assert_eq!(address[0].as_str(), "192.168.23.2");
                        assert_eq!(address[1].as_str(), "8.8.8.8");
                        assert_eq!(search[0].as_str(), "exemplary");
                        assert_eq!(interface, &Some("interface0".to_owned()))
                    }
                    not => {
                        panic!("expected nameserver network config, got {:?}", not)
                    }
                }
            }
            NetworkConfig::V2(_) => {
                panic!("expected v1 config got v2")
            }
        }
        Ok(())
    }

    #[test]
    fn parse_route () -> Result<(), failure::Error> {
        let cfg = parse_network_config(&PathBuf::from_str("./sample_data/network_config_v1/test_route.yaml")?)?;
        match cfg {
            NetworkConfig::V1(v1) => {
                match &v1.config[0] {
                    NetworkDataV1Iface::Physical { name, mac_address, subnets, .. } => {
                        assert_eq!(name.as_str(), "interface0");
                        assert_eq!(mac_address, &Some("00:11:22:33:44:55".to_owned()));
                        match subnets {
                            None => {
                                panic!("expected a subnet config in physical network config, got {:?}", subnets)
                            }
                            Some(nets) => {
                                let s0 = &nets[0];
                                match s0 {
                                    NetworkDataV1Subnet::Static(cfg) => {
                                        assert_eq!(cfg.address.as_str(), "192.168.23.14/24");
                                        assert_eq!(cfg.gateway, Some("192.168.23.1".to_owned()));
                                    }
                                    not => {
                                        panic!("expected static subnet config, got {:?}", not)
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        panic!("expected physical network config")
                    }
                }
                match &v1.config[1] {
                    NetworkDataV1Iface::Route { destination, gateway, metric } => {
                        assert_eq!(destination.as_str(), "192.168.24.0/24");
                        assert_eq!(gateway.as_str(), "192.168.24.1");
                        assert_eq!(metric, &3);
                    }
                    not => {
                        panic!("expected route network config, got {:?}", not)
                    }
                }
            }
            NetworkConfig::V2(_) => {
                panic!("expected v1 config got v2")
            }
        }
        Ok(())
    }

    #[test]
    fn parse_subnet_dhcp () -> Result<(), failure::Error> {
        let cfg = parse_network_config(&PathBuf::from_str("./sample_data/network_config_v1/test_subnet_dhcp.yaml")?)?;
        match cfg {
            NetworkConfig::V1(v1) => {
                match &v1.config[0] {
                    NetworkDataV1Iface::Physical { name, mac_address, subnets, .. } => {
                        assert_eq!(name.as_str(), "interface0");
                        assert_eq!(mac_address, &Some("00:11:22:33:44:55".to_owned()));
                        match subnets {
                            None => {
                                panic!("expected a subnet config in physical network config, got {:?}", subnets)
                            }
                            Some(nets) => {
                                let s0 = &nets[0];
                                match s0 {
                                    NetworkDataV1Subnet::Dhcp => {}
                                    not => {
                                        panic!("expected static subnet config, got {:?}", not)
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        panic!("expected physical network config")
                    }
                }
            }
            NetworkConfig::V2(_) => {
                panic!("expected v1 config got v2")
            }
        }
        Ok(())
    }

    #[test]
    fn parse_subnet_static () -> Result<(), failure::Error> {
        let cfg = parse_network_config(&PathBuf::from_str("./sample_data/network_config_v1/test_subnet_static.yaml")?)?;
        match cfg {
            NetworkConfig::V1(v1) => {
                match &v1.config[0] {
                    NetworkDataV1Iface::Physical { name, mac_address, subnets, .. } => {
                        assert_eq!(name.as_str(), "interface0");
                        assert_eq!(mac_address, &Some("00:11:22:33:44:55".to_owned()));
                        match subnets {
                            None => {
                                panic!("expected a subnet config in physical network config, got {:?}", subnets)
                            }
                            Some(nets) => {
                                let s0 = &nets[0];
                                match s0 {
                                    NetworkDataV1Subnet::Static(cfg) => {
                                        assert_eq!(cfg.address.as_str(), "192.168.23.14/27");
                                        assert_eq!(cfg.gateway, Some("192.168.23.1".to_owned()));
                                        match &cfg.dns_nameservers {
                                            None => {
                                                panic!("expecting a dns_nameservers key in testfile")
                                            }
                                            Some(nameservers) => {
                                                assert_eq!(nameservers[0].as_str(), "192.168.23.2");
                                                assert_eq!(nameservers[1].as_str(), "8.8.8.8");
                                            }
                                        }
                                        match &cfg.dns_search {
                                            None => {
                                                panic!("expecting a dns_search key in testfile")
                                            }
                                            Some(nameservers) => {
                                                assert_eq!(nameservers[0].as_str(), "exemplary.maas");
                                            }
                                        }
                                    }
                                    not => {
                                        panic!("expected static subnet config, got {:?}", not)
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        panic!("expected physical network config")
                    }
                }
            }
            NetworkConfig::V2(_) => {
                panic!("expected v1 config got v2")
            }
        }
        Ok(())
    }

    #[test]
    fn parse_subnet_multiple () -> Result<(), failure::Error> {
        let cfg = parse_network_config(&PathBuf::from_str("./sample_data/network_config_v1/test_subnet_multiple.yaml")?)?;
        match cfg {
            NetworkConfig::V1(v1) => {
                match &v1.config[0] {
                    NetworkDataV1Iface::Physical { name, mac_address, subnets, .. } => {
                        assert_eq!(name.as_str(), "interface0");
                        assert_eq!(mac_address, &Some("00:11:22:33:44:55".to_owned()));
                        match subnets {
                            None => {
                                panic!("expected a subnet config in physical network config, got {:?}", subnets)
                            }
                            Some(nets) => {
                                match &nets[0] {
                                    NetworkDataV1Subnet::Dhcp => {},
                                    not => {
                                        panic!("expected static subnet config, got {:?}", not)
                                    }
                                }
                                match &nets[1] {
                                    NetworkDataV1Subnet::Static(cfg) => {
                                        assert_eq!(cfg.address.as_str(), "192.168.23.14/27");
                                        assert_eq!(cfg.gateway, Some("192.168.23.1".to_owned()));
                                        match &cfg.dns_nameservers {
                                            None => {
                                                panic!("expecting a dns_nameservers key in testfile")
                                            }
                                            Some(nameservers) => {
                                                assert_eq!(nameservers[0].as_str(), "192.168.23.2");
                                                assert_eq!(nameservers[1].as_str(), "8.8.8.8");
                                            }
                                        }
                                        match &cfg.dns_search {
                                            None => {
                                                panic!("expecting a dns_search key in testfile")
                                            }
                                            Some(nameservers) => {
                                                assert_eq!(nameservers[0].as_str(), "exemplary");
                                            }
                                        }
                                    }
                                    not => {
                                        panic!("expected static subnet config, got {:?}", not)
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        panic!("expected physical network config")
                    }
                }
            }
            NetworkConfig::V2(_) => {
                panic!("expected v1 config got v2")
            }
        }
        Ok(())
    }

    #[test]
    fn parse_subnet_with_routes () -> Result<(), failure::Error> {
        let cfg = parse_network_config(&PathBuf::from_str("./sample_data/network_config_v1/test_subnet_with_routes.yaml")?)?;
        match cfg {
            NetworkConfig::V1(v1) => {
                match &v1.config[0] {
                    NetworkDataV1Iface::Physical { name, mac_address, subnets, .. } => {
                        assert_eq!(name.as_str(), "interface0");
                        assert_eq!(mac_address, &Some("00:11:22:33:44:55".to_owned()));
                        match subnets {
                            None => {
                                panic!("expected a subnet config in physical network config, got {:?}", subnets)
                            }
                            Some(nets) => {
                                match &nets[0] {
                                    NetworkDataV1Subnet::Dhcp => {},
                                    not => {
                                        panic!("expected static subnet config, got {:?}", not)
                                    }
                                }
                                match &nets[1] {
                                    NetworkDataV1Subnet::Static(cfg) => {
                                        assert_eq!(cfg.address.as_str(), "10.184.225.122");
                                        assert_eq!(cfg.netmask, Some("255.255.255.252".to_owned()));
                                        match &cfg.routes {
                                            None => {
                                                panic!("expecting a routes key in testfile")
                                            }
                                            Some(routes) => {
                                                assert_eq!(routes[0].gateway.as_str(), "10.184.225.121");
                                                assert_eq!(routes[0].netmask.as_str(), "255.240.0.0");
                                                assert_eq!(routes[0].network.as_str(), "10.176.0.0");
                                                assert_eq!(routes[1].gateway.as_str(), "10.184.225.121");
                                                assert_eq!(routes[1].netmask.as_str(), "255.240.0.0");
                                                assert_eq!(routes[1].network.as_str(), "10.208.0.0");
                                            }
                                        }
                                    }
                                    not => {
                                        panic!("expected static subnet config, got {:?}", not)
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        panic!("expected physical network config")
                    }
                }
            }
            NetworkConfig::V2(_) => {
                panic!("expected v1 config got v2")
            }
        }
        Ok(())
    }

    #[test]
    fn parse_subnet_bonded_vlan () -> Result<(), failure::Error> {
        let cfg = parse_network_config(&PathBuf::from_str("./sample_data/network_config_v1/test_bonded_vlan.yaml")?)?;
        match cfg {
            NetworkConfig::V1(v1) => {
                match &v1.config[0] {
                    NetworkDataV1Iface::Physical { name, mac_address, .. } => {
                        assert_eq!(name.as_str(), "gbe0");
                        assert_eq!(mac_address, &Some("cd:11:22:33:44:00".to_owned()));
                    }
                    not => {
                        panic!("expected physical network config, got: {:?}", not)
                    }
                }
                match &v1.config[1] {
                    NetworkDataV1Iface::Physical { name, mac_address, .. } => {
                        assert_eq!(name.as_str(), "gbe1");
                        assert_eq!(mac_address, &Some("cd:11:22:33:44:02".to_owned()));
                    }
                    not => {
                        panic!("expected physical network config, got: {:?}", not)
                    }
                }
                match &v1.config[2] {
                    NetworkDataV1Iface::Bond { name, bond_interfaces, params, .. } => {
                        assert_eq!(name.as_str(), "bond0");
                        assert_eq!(bond_interfaces[0].as_str(), "gbe0");
                        assert_eq!(bond_interfaces[1].as_str(), "gbe1");
                        assert_eq!(params["bond-mode"].as_str(), "802.3ad");
                        assert_eq!(params["bond-lacp-rate"].as_str(), "fast");
                    }
                    not => {
                        panic!("expected bond network config, got: {:?}", not)
                    }
                }
                match &v1.config[3] {
                    NetworkDataV1Iface::Vlan { name, vlan_link, vlan_id, subnets, .. } => {
                        assert_eq!(name.as_str(), "bond0.200");
                        assert_eq!(vlan_link.as_str(), "bond0");
                        assert_eq!(vlan_id, &200);
                        match subnets {
                            None => {
                                panic!("expected subnet network config for vlan, got: {:?}", &v1.config[3])
                            }
                            Some(nets) => {
                                match &nets[0] {
                                    NetworkDataV1Subnet::Dhcp4 => {}
                                    not => {
                                        panic!("expected dhcp4 subnet config, got: {:?}", not)
                                    }
                                }
                            }
                        }
                    }
                    not => {
                        panic!("expected vlan network config, got: {:?}", not)
                    }
                }
            }
            NetworkConfig::V2(_) => {
                panic!("expected v1 config got v2")
            }
        }
        Ok(())
    }

    #[test]
    fn parse_multiple_vlan () -> Result<(), failure::Error> {
        let cfg = parse_network_config(&PathBuf::from_str("./sample_data/network_config_v1/test_multiple_vlan.yaml")?)?;
        match cfg {
            NetworkConfig::V1(v1) => {
                match &v1.config[0] {
                    NetworkDataV1Iface::Physical { name, mac_address, mtu, subnets, .. } => {
                        assert_eq!(name.as_str(), "eth0");
                        assert_eq!(mac_address, &Some("d4:be:d9:a8:49:13".to_owned()));
                        assert_eq!(mtu, &Some(1500));
                        match subnets {
                            None => {
                                panic!("expected subnet network config for eth0, got: {:?}", &v1.config[0])
                            }
                            Some(nets) => {
                                match &nets[0] {
                                    NetworkDataV1Subnet::Static(st0) => {
                                        assert_eq!(st0.address.as_str(), "10.245.168.16/21");
                                        assert_eq!(st0.gateway, Some("10.245.168.1".to_owned()));
                                        if let Some(dns) = &st0.dns_nameservers {
                                            assert_eq!(dns[0].as_str(), "10.245.168.2")
                                        }
                                    }
                                    not => {
                                        panic!("expected static subnet config, got: {:?}", not)
                                    }
                                }
                            }
                        }
                    }
                    not => {
                        panic!("expected physical network config, got: {:?}", not)
                    }
                }
                match &v1.config[1] {
                    NetworkDataV1Iface::Physical { name, mac_address, mtu, subnets, .. } => {
                        assert_eq!(name.as_str(), "eth1");
                        assert_eq!(mac_address, &Some("d4:be:d9:a8:49:15".to_owned()));
                        assert_eq!(mtu, &Some(1500));
                        match subnets {
                            None => {
                                panic!("expected subnet network config for eth1, got: {:?}", &v1.config[1])
                            }
                            Some(nets) => {
                                match &nets[0] {
                                    NetworkDataV1Subnet::Static(st0) => {
                                        assert_eq!(st0.address.as_str(), "10.245.188.2/24");
                                        if let Some(dns) = &st0.dns_nameservers {
                                            assert_eq!(dns.len(), 0);
                                        }
                                    }
                                    not => {
                                        panic!("expected static subnet config, got: {:?}", not)
                                    }
                                }
                            }
                        }
                    }
                    not => {
                        panic!("expected physical network config, got: {:?}", not)
                    }
                }
                match &v1.config[2] {
                    NetworkDataV1Iface::Vlan { name, mtu, vlan_id, vlan_link, subnets, .. } => {
                        assert_eq!(name.as_str(), "eth1.2667");
                        assert_eq!(vlan_link.as_str(), "eth1");
                        assert_eq!(mtu, &Some(1500));
                        assert_eq!(vlan_id, &2667);
                        match subnets {
                            None => {
                                panic!("expected subnet network config for eth1, got: {:?}", &v1.config[2])
                            }
                            Some(nets) => {
                                match &nets[0] {
                                    NetworkDataV1Subnet::Static(st0) => {
                                        assert_eq!(st0.address.as_str(), "10.245.184.2/24");
                                        if let Some(dns) = &st0.dns_nameservers {
                                            assert_eq!(dns.len(), 0);
                                        }
                                    }
                                    not => {
                                        panic!("expected static subnet config, got: {:?}", not)
                                    }
                                }
                            }
                        }
                    }
                    not => {
                        panic!("expected physical network config, got: {:?}", not)
                    }
                }
                match &v1.config[3] {
                    NetworkDataV1Iface::Vlan { name, mtu, vlan_id, vlan_link, subnets, .. } => {
                        assert_eq!(name.as_str(), "eth1.2668");
                        assert_eq!(vlan_link.as_str(), "eth1");
                        assert_eq!(mtu, &Some(1500));
                        assert_eq!(vlan_id, &2668);
                        match subnets {
                            None => {
                                panic!("expected subnet network config for eth1, got: {:?}", &v1.config[3])
                            }
                            Some(nets) => {
                                match &nets[0] {
                                    NetworkDataV1Subnet::Static(st0) => {
                                        assert_eq!(st0.address.as_str(), "10.245.185.1/24");
                                        if let Some(dns) = &st0.dns_nameservers {
                                            assert_eq!(dns.len(), 0);
                                        }
                                    }
                                    not => {
                                        panic!("expected static subnet config, got: {:?}", not)
                                    }
                                }
                            }
                        }
                    }
                    not => {
                        panic!("expected physical network config, got: {:?}", not)
                    }
                }
                match &v1.config[4] {
                    NetworkDataV1Iface::Vlan { name, mtu, vlan_id, vlan_link, subnets, .. } => {
                        assert_eq!(name.as_str(), "eth1.2669");
                        assert_eq!(vlan_link.as_str(), "eth1");
                        assert_eq!(mtu, &Some(1500));
                        assert_eq!(vlan_id, &2669);
                        match subnets {
                            None => {
                                panic!("expected subnet network config for eth1, got: {:?}", &v1.config[4])
                            }
                            Some(nets) => {
                                match &nets[0] {
                                    NetworkDataV1Subnet::Static(st0) => {
                                        assert_eq!(st0.address.as_str(), "10.245.186.1/24");
                                        if let Some(dns) = &st0.dns_nameservers {
                                            assert_eq!(dns.len(), 0);
                                        }
                                    }
                                    not => {
                                        panic!("expected static subnet config, got: {:?}", not)
                                    }
                                }
                            }
                        }
                    }
                    not => {
                        panic!("expected physical network config, got: {:?}", not)
                    }
                }
                match &v1.config[5] {
                    NetworkDataV1Iface::Vlan { name, mtu, vlan_id, vlan_link, subnets, .. } => {
                        assert_eq!(name.as_str(), "eth1.2670");
                        assert_eq!(vlan_link.as_str(), "eth1");
                        assert_eq!(mtu, &Some(1500));
                        assert_eq!(vlan_id, &2670);
                        match subnets {
                            None => {
                                panic!("expected subnet network config for eth1, got: {:?}", &v1.config[5])
                            }
                            Some(nets) => {
                                match &nets[0] {
                                    NetworkDataV1Subnet::Static(st0) => {
                                        assert_eq!(st0.address.as_str(), "10.245.187.2/24");
                                        if let Some(dns) = &st0.dns_nameservers {
                                            assert_eq!(dns.len(), 0);
                                        }
                                    }
                                    not => {
                                        panic!("expected static subnet config, got: {:?}", not)
                                    }
                                }
                            }
                        }
                    }
                    not => {
                        panic!("expected physical network config, got: {:?}", not)
                    }
                }
                match &v1.config[6] {
                    NetworkDataV1Iface::Nameserver { address, search, .. } => {
                        assert_eq!(address[0].as_str(), "10.245.168.2");
                        assert_eq!(search[0].as_str(), "dellstack");
                    }
                    not => {
                        panic!("expected nameserver network config, got: {:?}", not)
                    }
                }
            }
            NetworkConfig::V2(_) => {
                panic!("expected v1 config got v2")
            }
        }
        Ok(())
    }
}