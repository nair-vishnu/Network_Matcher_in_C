# Network_Matcher_in_C

Helpers:

1. Use the following command to compile the eBPF program:
   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c trace_dev_queue.c -o trace_dev_queue.o

2. For user program:
	gcc -o trace_dev_queue_user trace_dev_queue_user.c -lbpf

3. Start a python server:
   python3 -m http.server 8080 & SERVER_PID=$!

4. Curl requests:
   curl http://localhost:8080
   
5. Run ebpf tracer:
	sudo ./trace_dev_queue_user $SERVER_PID

6. Kernel logs and trace pipe:
	sudo cat /sys/kernel/debug/tracing/trace_pipe
