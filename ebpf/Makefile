## ebpf/Makefile — Build targets for JA4proxy XDP/eBPF programs
##
## Prerequisites: clang, linux-headers, libbpf-dev
##   sudo apt install clang linux-headers-$(uname -r) libbpf-dev

BPF_TARGET = ja4block.o
CC         = clang
CFLAGS     = -O2 -target bpf -Wall

.PHONY: all clean

all: $(BPF_TARGET)

$(BPF_TARGET): ja4block.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o
