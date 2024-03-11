project('lsm_bpf', 'c')

libbpf = dependency('libbpf')
bpftool = find_program('bpftool')

vmlinux = custom_target(
  'vmlinux',
  command: [bpftool, 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 'format', 'c'],
  capture: true,
  output: 'vmlinux.h',
)

bpf_args = [
  '-g',  # BTF instrumentation
  '-O2', # required for libbpf
  '-D__KERNEL__',
  '-D__TARGET_ARCH_x86',
  '--target=bpf',
]
lsm_bpf = static_library('lsm_bpf', ['lsm.bpf.c', vmlinux], c_args: bpf_args)

lsm_bpf_skel = custom_target(
  'lsm_bpf_skel',
  depends: lsm_bpf,
  command: [bpftool, 'gen', 'skeleton', 'liblsm_bpf.a.p/lsm.bpf.c.o'],
  capture: true,
  output: 'lsm_bpf.skel.h',
)

executable( 'lsm_bpf', ['lsm.user.c', lsm_bpf_skel], dependencies: libbpf, install: true)
