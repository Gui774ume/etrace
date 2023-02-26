ARCH ?= x86

all: build

build-ebpf:
	mkdir -p ebpf/assets/bin
	clang -D__KERNEL__ \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-I/lib/modules/$$(uname -r)/build/include \
		-I/lib/modules/$$(uname -r)/build/include/uapi \
		-I/lib/modules/$$(uname -r)/build/include/generated/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/$(ARCH)/include \
		-I/lib/modules/$$(uname -r)/build/arch/$(ARCH)/include/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/$(ARCH)/include/generated \
		-c -O2 -g -target bpf \
		ebpf/main.c \
		-o ebpf/assets/bin/probe.o

build:
	mkdir -p bin/
	go build -o bin/ ./cmd/...

run:
	sudo ./bin/etrace --log-level debug

install:
	sudo cp ./bin/etrace /usr/bin/
