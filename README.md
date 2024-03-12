# inf8602-mini-project

## Prerequisites

- [Vagrant](https://developer.hashicorp.com/vagrant/install)
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
- [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html#selecting-an-ansible-package-and-version-to-install)

## Quickstart

Bootstrap the VM and try the PoC:

- [How to reproduce](#how-to-reproduce)

Enable mitigations:

```sh
vagrant provision --provision-with ansible
vagrant ssh -c 'ssh john@localhost'
```

## References

- https://wiki.debian.org/SELinux/Setup#Steps_to_setup_SELinux
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/using_selinux/index
- https://wiki.gentoo.org/wiki/SELinux

# CVE-2023-0386

This folder contains a virtual machine and instructions to reproduce [CVE-2023-0386](https://nvd.nist.gov/vuln/detail/CVE-2023-0386), a vulnerability in the Linux kernel’s OverlayFS subsystem that allows an unprivileged user to escalate their privileges to root.

## How to reproduce

* Start the virtual machine (based on Ubuntu 22.04.1, kernel 5.15.0-57-generic):

```
vagrant up
```

* SSH to the machine as an unprivileged user:

```
vagrant ssh --command "sudo su john -c 'cd; bash'"
```

```bash
john@ubuntu-jammy:~$ id
uid=1002(john) gid=1002(john) groups=1002(john)
```

* Exploit

The virtual machine is provisioned with an exploit merging the different pieces of this [proof of concept repository](https://github.com/xkaneiki/CVE-2023-0386/) into one single static binary. This binary creates folders tree under `/tmp/ovlcap` and starts FUSE filesystem which serves an suid executable. It then calls `unshare` with mount overlay command and copy of the lower suid executable. Finally, it runs the suid executable to spawn a root shell.

Run the following command to exploit the vulnerability and escalate to root:

```
./poc
```

<p align="center">
   <img src="screenshot.png" width="650" />
</p>

## Credits

Proof-of-concept: https://github.com/xkaneiki/CVE-2023-0386/
Reproduction for Datadog: Ryan Simon and Fred Baguelin
