/*
 * Copyright 2021 OpenFlowLabs
 *
 */
use std::collections::HashMap;
use serde::{Deserialize};
use crate::userdata::multiformat_deserialize::Multiformat;

#[derive(Default, Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct Metadata {
    #[serde(rename = "instance-id")]
    pub instance_id: String,
    #[serde(rename = "instance-type")]
    pub instance_type: Option<String>,
    #[serde(rename = "network-interfaces")]
    pub network_interfaces: Option<String>,
    pub hostname: Option<String>,
    #[serde(rename = "local-hostname")]
    pub local_hostname: Option<String>,
    #[serde(rename = "public-hostname")]
    pub public_hostname: Option<String>,
    pub placement: Option<PlacementData>,
}

impl Metadata {
    pub fn get_hostname(&self) -> &str {
        if let Some(name) = &self.public_hostname {
            return name;
        }

        if let Some(name) = &self.hostname {
            return name;
        }

        if let Some(name) = &self.local_hostname {
            return name;
        }

        ""
    }

    pub fn get_public_hostname(&self) -> &str {
        if let Some(name) = &self.public_hostname {
            return name;
        }

        ""
    }
}

#[derive(Default, Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct PlacementData {
    #[serde(rename = "availability-zone")]
    pub availability_zone: Option<String>,
    #[serde(rename = "group-name")]
    pub group_name: Option<String>,
    #[serde(rename = "partition-number")]
    pub partition_number: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct CloudConfig {
    pub groups: Option<Vec<HashMap<String, Option<Vec<String>>>>>,
    pub users: Vec<UserConfig>,
    pub write_files: Option<Vec<WriteFileData>>,
    #[serde(rename = "ca-certs")]
    pub ca_certs: Option<CaCertsData>,
    pub bootcmd: Option<Multiformat>,
    pub runcms: Option<Multiformat>,
    pub final_message: Option<String>,
    pub packages: Option<Multiformat>,
    pub package_update: Option<bool>,
    pub phone_home: Option<PhoneHomeData>,
    pub growpart: Option<GrowPartData>,
    pub ssh_authorized_keys: Option<Vec<String>>,
    pub ssh_keys: Option<HashMap<String, String>>,
    pub no_ssh_fingerprints: Option<bool>,
    pub ssh: Option<HashMap<String, bool>>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct UserConfig {
    pub name: String,
    #[serde(rename = "expiredate")]
    pub expire_date: Option<String>,
    pub gecos: Option<String>,
    pub homedir: Option<String>,
    pub primary_group: Option<String>,
    pub groups: Option<Vec<String>>,
    pub lock_passwd: Option<bool>,
    pub inactive: Option<String>,
    pub passwd: Option<String>,
    pub no_create_home: Option<bool>,
    pub no_user_group: Option<bool>,
    pub ssh_authorized_keys: Option<Vec<String>>,
    pub system: Option<bool>,
    pub shell: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub enum GrowPartMode {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "growpart")]
    Growpart,
    #[serde(rename = "off")]
    Off
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct GrowPartData {
    pub mode: GrowPartMode,
    pub devices: Vec<String>,
    pub ignore_growroot_disabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub enum PowerStateMode {
    #[serde(rename = "poweroff")]
    Poweroff,
    #[serde(rename = "halt")]
    Halt,
    #[serde(rename = "reboot")]
    Reboot
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct PowerStateData {
    pub delay: String,
    pub mode: PowerStateMode,
    pub message: String,
    pub timeout: String,
    // TODO figure out how to parse string or list case
    pub condition: String,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct PhoneHomeData {
    pub url: String,
    pub post: Vec<String>,
    pub tries: i32,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct CaCertsData {
    #[serde(rename = "remove-defaults")]
    pub remove_defaults: bool,
    pub trusted: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub enum WriteFileEncoding {
    None,
    B64,
    Gzip,
    B64Gzip
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct WriteFileData {
    // TODO Figure out how to deserialize
    pub encoding: WriteFileEncoding,
    pub content: String,
    pub owner: Option<String>,
    pub path: String,
    pub permissions: Option<String>,
}
