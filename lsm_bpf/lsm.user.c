#include <bpf/libbpf.h>
#include <unistd.h>
#include "lsm_bpf.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[])
{
    struct lsm_bpf_c *skel;
    int err = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    // Loads and verifies the BPF program
    skel = lsm_bpf_c__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // Attaches the loaded BPF program to the LSM hook
    err = lsm_bpf_c__attach(skel);
    if (err)
    {
        fprintf(stderr, "failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("LSM loaded! ctrl+c to exit.\n");

    // The BPF link is not pinned, therefore exiting will remove program
    for (;;)
    {
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    lsm_bpf_c__destroy(skel);
    return err;
}
