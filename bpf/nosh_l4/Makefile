CLANG ?= clang
BPFTOOL ?= bpftool
CC ?= cc
IG ?= ig
NODE ?= node
PKG_CONFIG ?= pkg-config

BPF_SOURCE := nosh_l4.bpf.c
VMLINUX := vmlinux.h
BUILD_DIR := build
BPF_OBJECT := $(BUILD_DIR)/nosh_l4.bpf.o
SKELETON := $(BUILD_DIR)/nosh_l4.skel.h
LOADER_SOURCE := loader/nosh_l4_loader.c
LOADER_BINARY := $(BUILD_DIR)/nosh-l4-loader
GADGET_TAG ?= ghcr.io/example/nosh-l4-evidence:dev
PREFIX ?= /usr/local
LOADER_INSTALL_DIR ?= $(PREFIX)/libexec/nosh-guard

UNAME_M := $(shell uname -m)
ifndef BPF_ARCH
ifeq ($(UNAME_M),x86_64)
BPF_ARCH := x86
else ifeq ($(UNAME_M),aarch64)
BPF_ARCH := arm64
else ifeq ($(UNAME_M),arm64)
BPF_ARCH := arm64
else ifeq ($(UNAME_M),s390x)
BPF_ARCH := s390
else ifeq ($(UNAME_M),ppc64le)
BPF_ARCH := powerpc
else ifeq ($(UNAME_M),riscv64)
BPF_ARCH := riscv
else
$(error Unsupported architecture $(UNAME_M); set BPF_ARCH explicitly)
endif
endif

BPF_CFLAGS ?= -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH)
BPF_CFLAGS += -I. -Iinclude

LOADER_CFLAGS ?= -g -O2 -std=c17 -Wall -Wextra
LIBBPF_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS ?= $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null)
ifeq ($(strip $(LIBBPF_LIBS)),)
LIBBPF_LIBS := -lbpf -lelf -lz
endif

.PHONY: all object skeleton loader install-loader gadget test clean

all: loader

object: $(BPF_OBJECT)

$(VMLINUX):
	@test -r /sys/kernel/btf/vmlinux || \
		{ echo "host kernel BTF is unavailable at /sys/kernel/btf/vmlinux" >&2; exit 1; }
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp
	mv $@.tmp $@

$(BUILD_DIR):
	mkdir -p $@

$(BPF_OBJECT): $(BPF_SOURCE) include/nosh_l4.h $(VMLINUX) | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SOURCE) -o $@

skeleton: $(SKELETON)

$(SKELETON): $(BPF_OBJECT)
	$(BPFTOOL) gen skeleton $(BPF_OBJECT) name nosh_l4_bpf > $@.tmp
	mv $@.tmp $@

loader: $(LOADER_BINARY)

$(LOADER_BINARY): $(LOADER_SOURCE) include/nosh_l4.h $(SKELETON)
	$(CC) $(LOADER_CFLAGS) $(LIBBPF_CFLAGS) \
		-Iinclude -I$(BUILD_DIR) $(LOADER_SOURCE) \
		-o $@ $(LIBBPF_LIBS)

install-loader: $(LOADER_BINARY)
	install -d -o root -g root -m 0755 $(DESTDIR)$(LOADER_INSTALL_DIR)
	install -o root -g root -m 0755 $(LOADER_BINARY) \
		$(DESTDIR)$(LOADER_INSTALL_DIR)/nosh-l4-loader

gadget:
	$(IG) image build . -f build.yaml -t $(GADGET_TAG)

test:
	$(NODE) --test tests/*.test.cjs

clean:
	rm -f $(BPF_OBJECT) $(SKELETON) $(LOADER_BINARY) $(VMLINUX) \
		$(VMLINUX).tmp $(SKELETON).tmp
	rmdir $(BUILD_DIR) 2>/dev/null || true
