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
* Amazon EC2
* Generic QEMU/KVM; e.g., under `libvirtd`
* VMware Fusion

The software is expected to work on at least the following illumos
distributions:

* [OmniOS](https://omnios.org/)
* [OpenIndiana](https://www.openindiana.org/)
* [Tribblix](http://www.tribblix.org/)

## Building and Usage

This software must be built with Rust and Cargo. for convenience a Makefile is provided

```
$ gmake MODE=release
```

The built artefact, `target/release/metadata`, is intended to be installed as
`/usr/lib/metadata`.  In addition, `userscript.sh` is intended to be installed
as `/usr/lib/userscript.sh` and made executable.

Finally, [SMF](https://illumos.org/man/5/smf) service manifests are provided
for both the metadata service (`metadata.xml`) and the service which executes a
user-provided script (`userscript.xml`), and are intended to be included in the
image in `/lib/svc/manifest/system`.

The Makefile automates this aswell if wanted
```
$ gmake install MODE=release
```

It is desirable to include these services in the SMF seed repository for an
image so that they are already imported when the image first boots in the
guest.  The services include dependent relationships with several early boot
networking and identity services in an attempt to ensure the metadata agent
runs before network services are completely online.

## Packaging
If you would like to package this binary use the following command in your build
system to create a prototype directory tree.

`proto` can be any directory path of your choosing. 

```
$ gmake DESTDIR=proto
```