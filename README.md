# illumos Metadata Agent

This agent runs early in boot to configure an illumos virtual machine using the
metadata provided by the hypervisor or cloud environment.  The agent supports
the configuration of:

* networking (IP addresses, DNS servers, and the default gateway)
* credentials (SSH keys)
* hostname
* swap space
* expansion of the ZFS pool to fill the provisioned root device
* regeneration of ZFS pool unique ID (`zpool reguid`) in the image
* optional execution of a user-provided script

At present, the following hypervisors or cloud environments are supported on
some level:

* Joyent SmartOS (including Triton environments)
* DigitalOcean
* Vultr
* Amazon EC2
* Generic QEMU/KVM; e.g., under `libvirtd`
* VMware Fusion

The software is expected to work on at least the following illumos
distributions:

* [OmniOS](https://omnios.org/)
* [OpenIndiana](https://www.openindiana.org/)
* [Tribblix](http://www.tribblix.org/)

## Building and Usage

This software must be built with Rust and Cargo.

```
$ cargo build --release
```

The built artefact, `target/release/metadata`, is intended to be installed as
`/usr/lib/metadata`.  In addition, `userscript.sh` is intended to be installed
as `/usr/lib/userscript.sh` and made executable.

Finally, [SMF](https://illumos.org/man/5/smf) service manifests are provided
for both the metadata service (`metadata.xml`) and the service which executes a
user-provided script (`userscript.xml`), and are intended to be included in the
image in `/lib/svc/manifest/system`.

It is desirable to include these services in the SMF seed repository for an
image so that they are already imported when the image first boots in the
guest.  The services include dependent relationships with several early boot
networking and identity services in an attempt to ensure the metadata agent
runs before network services are completely online.

## Metadata CPIO Device

Not all hypervisor environments provide a self-describing configuration
metadata service.  In order to ease the creation of automatically configured
guests in such hypervisor environments, the metadata agent will fall back to
searching for a block device that contains a CPIO archive containing
configuration files.  Note that no file system is expected on the device, just
the output of `cpio -o` starting at LBA 0 of the emulated disk.

The following configuration files may appear in the CPIO archive:

- `nodename` (optional)

  A plain text file with the hostname to use for the guest on the first
  line of the file.  This name will be used to populate
  [nodename(5)](https://illumos.org/man/5/nodename) and
  [hosts(5)](https://illumos.org/man/5/hosts), and the live hostname
  as reported by [hostname(1)](https://illumos.org/man/1/hostname).

- `authorized_keys` (optional)

  This file will be installed as `/root/.ssh/authorized_keys` and should
  contain a list of SSH keys in the usual format expected by `sshd`.

- `config.toml` (optional)

  This TOML-formatted file can contain overrides and other configuration.
  At present, only one key is supported:

  * `network.skip` (boolean, optional, defaults to `false`)

  For example, the following configuration file will cause the metadata
  agent to skip any attempt to use DHCP to configure a network
  interface:

  ```toml
  [network]
  skip = true
  ```

- `firstboot.sh` (optional)

  This file may contain a shell script that will be started on first boot.

  Once the script has completed, the system will try not to start the script
  again on subsequent boots.  If the system crashes part way through running
  the script, or there is some other unexpected failure, it may not be possible
  to record that the script completed and it may be started again immediately
  or on subsequent boots.  As such, the provided script should be idempotent.

  The provided script must begin with a valid interpreter line; e.g.,

  ```sh
  #!/bin/bash

  echo ok
  ```
