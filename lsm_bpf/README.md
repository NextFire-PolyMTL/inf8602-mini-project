# lsm_bpf

LSM BPF program that mitigates CVE-2023-0386 by restricting SUID file copy up from lower layer to upper layer of overlayfs.

```sh
meson setup build
meson compile -C build
meson install -C build
```
