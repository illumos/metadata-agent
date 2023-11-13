/*
 * Copyright 2023 Oxide Computer Company
 */

pub mod amazon;
pub mod digitalocean;
pub mod generic;
pub mod nocloud;
pub mod smartos;

mod prelude {
    pub(crate) use crate::common::*;
    pub(crate) use crate::{
        dhcpinfo, dladm_ether_list, ensure_dir, ensure_ipadm_interface,
        ensure_ipv4_gateway, ensure_ipv4_interface, ensure_ipv4_interface_dhcp,
        exists_dir, exists_file, exists_zvol, find_device, ipadm_address_list,
        mac_to_nic, mounts, netmask_to_prefix_len, nic_to_mac, phase_add_swap,
        phase_dns, phase_expand_zpool, phase_pubkeys, phase_reguid_zpool,
        phase_set_hostname, phase_userscript, read_file, read_json, read_lines,
        read_toml, write_lines, Config, CPIO, MOUNT, MOUNTPOINT, ROUTE, STAMP,
        UNPACKDIR,
    };
}
