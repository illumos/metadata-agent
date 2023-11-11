/*
 * Copyright 2023 Oxide Computer Company
 */

pub mod amazon;
pub mod digitalocean;
pub mod generic;
pub mod smartos;

mod prelude {
    pub(crate) use crate::common::*;
    pub(crate) use crate::{
        dhcpinfo, dladm_ether_list, ensure_dir, ensure_ipadm_interface,
        ensure_ipv4_gateway, ensure_ipv4_interface, ensure_ipv4_interface_dhcp,
        exists_dir, exists_file, exists_zvol, mounts, phase_add_swap,
        phase_dns, phase_expand_zpool, phase_pubkeys, phase_reguid_zpool,
        phase_set_hostname, phase_userscript, read_file, read_json, read_lines,
        read_toml, write_lines, Config, CPIO, MOUNT, MOUNTPOINT, STAMP,
        UNPACKDIR,
    };
}
