#include <stdio.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h> // For strerror

static volatile int keep_running = 1;

void handle_sigint(int sig) {
    keep_running = 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int err;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <PID of the Python server>\n", argv[0]);
        return 1;
    }

    uint32_t target_pid = atoi(argv[1]);

    signal(SIGINT, handle_sigint);

    // Load BPF object from .o file
    obj = bpf_object__open_file("trace_dev_queue.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(-libbpf_get_error(obj)));
        return 1;
    }

    // Load the BPF program into the kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        return 1;
    }

    // Find and attach the egress program
    prog = bpf_object__find_program_by_name(obj, "handle_dev_queue_xmit");
    if (!prog) {
        fprintf(stderr, "Failed to find egress program in BPF object\n");
        return 1;
    }

    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Failed to attach egress BPF program\n");
        return 1;
    }

    printf("Tracing packets from process PID %u... Press Ctrl+C to stop.\n", target_pid);

    // Event loop
    while (keep_running) {
        sleep(1);
    }

    // Clean up
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
