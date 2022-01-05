use std::collections::HashMap;
use crate::common::*;
use std::process::Command;
use users::{get_group_by_name, get_user_by_name, get_user_groups};
use crate::userdata::cloudconfig::UserConfig;
use crate::public_keys::ensure_pubkeys;

const GROUPADD: &str = "/usr/sbin/groupadd";
const USERMOD: &str = "/usr/sbin/usermod";
const USERADD: &str = "/usr/sbin/useradd";
const PASSWD: &str = "/usr/bin/passwd";

pub fn ensure_group(group: HashMap<String, Option<Vec<String>>>) -> Result<(), failure::Error> {
    if let Some(group_name) = group.keys().next(){
        let system_group = get_group_by_name(&group_name);
        match system_group {
            None => {
                let output = Command::new(GROUPADD)
                    .env_clear()
                    .arg(&group_name)
                    .output()?;

                if !output.status.success() {
                    bail!("could not create group {}: {}", group_name, output.info())
                }
            }
            _ => {}
        }

        if let Some(members) = group[group_name].clone() {
            for member in members {
                let user_option = get_user_by_name(&member);
                if let Some(user) = user_option {
                    let groups = get_user_groups(user.name(), user.primary_group_id());

                    if let Some(grps) = groups {
                        let mut current_groups: Vec<String> = grps.iter().map(|g| { String::from(g.name().to_string_lossy()) }).collect();
                        current_groups.push(group_name.to_string());
                        let new_groups_string: String = current_groups.join(",");
                        let output = Command::new(USERMOD)
                            .env_clear()
                            .arg("-G")
                            .arg(new_groups_string)
                            .arg(&member)
                            .output()?;
                        if !output.status.success() {
                            bail!("failed to set groups of user {}: {}", member, output.info())
                        }
                    }
                }

            }
        }
    } else {
        bail!("no key in groups configuration error: we have {:#?} in the config", group)
    }


    Ok(())
}

pub fn ensure_user(log: &Logger, user: &UserConfig) -> Result<(), failure::Error> {
    if let None = users::get_user_by_name(&user.name) {
        let mut useradd = Command::new(USERADD);
        useradd.env_clear();
        if let Some(d) = &user.expire_date {
            useradd.arg("-e");
            useradd.arg(d);
        }

        if let Some(g) = &user.gecos {
            useradd.arg("-c");
            useradd.arg(g);
        }

        if let Some(h) = &user.homedir {
            useradd.arg("-d");
            useradd.arg(h);
        }

        if let Some(g) = &user.primary_group {
            useradd.arg("-g");
            useradd.arg(g);
        }

        if let Some(gs) = &user.groups {
            useradd.arg("-G");
            useradd.arg(gs.join(","));
        }

        if user.system == None && user.no_create_home == None {
            useradd.arg("-m");
            useradd.arg("-z");
        }

        if let Some(s) = &user.shell {
            useradd.arg("-s");
            useradd.arg(s);
        }

        useradd.arg(&user.name);

        let output = useradd.output()?;

        if !output.status.success() {
            bail!("failed to run useradd for {}", user.name)
        }
    } else {
        info!(log, "user {} exists skipping", user.name)
    }

    if let Some(keys) = &user.ssh_authorized_keys {
        ensure_pubkeys(log, &user.name, keys)?;
    }

    let output = Command::new(PASSWD)
        .env_clear()
        .arg("-N")
        .arg(&user.name)
        .output()?;
    if !output.status.success() {
        bail!("failed to run passwd for {}", user.name)
    }

    Ok(())
}