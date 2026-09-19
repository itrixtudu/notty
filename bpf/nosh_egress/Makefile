CLANG ?= clang
BPFTOOL ?= bpftool
CC ?= cc
NODE ?= node
PKG_CONFIG ?= pkg-config

BPF_SOURCE := nosh_egress.bpf.c
VMLINUX := vmlinux.h
BUILD_DIR := build
BPF_OBJECT := $(BUILD_DIR)/nosh_egress.bpf.o
SKELETON := $(BUILD_DIR)/nosh_egress.skel.h
OBJECT_DIGEST_HEADER := $(BUILD_DIR)/nosh_egress_object_digest.h
LOADER_SOURCE := loader/nosh_egress_loader.c
LOADER_BINARY := $(BUILD_DIR)/nosh-egress-loader
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

BPF_CFLAGS ?= -g -O2 -target bpf -mcpu=v3 -D__TARGET_ARCH_$(BPF_ARCH)
BPF_CFLAGS += -I. -Iinclude
LOADER_CFLAGS ?= -g -O2 -std=c17 -Wall -Wextra -Werror
LIBBPF_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS ?= $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null)
ifeq ($(strip $(LIBBPF_LIBS)),)
LIBBPF_LIBS := -lbpf -lelf -lz
endif

.DELETE_ON_ERROR:

.PHONY: all object skeleton loader install-loader test test-kernel clean

all: loader

object: $(BPF_OBJECT)

skeleton: $(SKELETON)

$(VMLINUX):
	@test -r /sys/kernel/btf/vmlinux || \
		{ echo "host kernel BTF is unavailable" >&2; exit 1; }
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp
	mv $@.tmp $@

$(BUILD_DIR):
	mkdir -p $@

$(BPF_OBJECT): $(BPF_SOURCE) include/nosh_egress.h include/nosh_egress_dns_commit.h include/nosh_egress_dns_parse.h include/nosh_egress_dns_stage.h include/nosh_egress_dns_match.h include/nosh_egress_dns_grant.h include/nosh_egress_dns_wire.h tests/check-bpf-object.cjs $(VMLINUX) | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SOURCE) -o $@
	$(NODE) tests/check-bpf-object.cjs $@

$(SKELETON): $(BPF_OBJECT)
	$(BPFTOOL) gen skeleton $(BPF_OBJECT) name nosh_egress_bpf > $@.tmp
	mv $@.tmp $@

loader: $(LOADER_BINARY)

$(OBJECT_DIGEST_HEADER): $(BPF_OBJECT)
	@digest=$$(sha256sum $(BPF_OBJECT) | awk '{print $$1}'); \
		printf '#define NOSH_EGRESS_OBJECT_DIGEST "sha256:%s"\n' "$$digest" > $@.tmp
	mv $@.tmp $@

$(LOADER_BINARY): $(LOADER_SOURCE) include/nosh_egress.h $(SKELETON) $(OBJECT_DIGEST_HEADER)
	$(CC) $(LOADER_CFLAGS) $(LIBBPF_CFLAGS) \
		-Iinclude -I$(BUILD_DIR) $(LOADER_SOURCE) \
		-o $@ $(LIBBPF_LIBS)

install-loader: $(LOADER_BINARY)
	install -d -o root -g root -m 0755 $(DESTDIR)$(LOADER_INSTALL_DIR)
	install -o root -g root -m 0755 $(LOADER_BINARY) \
		$(DESTDIR)$(LOADER_INSTALL_DIR)/nosh-egress-loader

test:
	bash tests/static.sh
	$(NODE) --test tests/check-bpf-object.test.cjs
	CC="$(CC)" bash tests/dns-commit.sh
	CC="$(CC)" bash tests/dns-parse.sh
	CC="$(CC)" bash tests/dns-stage.sh
	CC="$(CC)" bash tests/loader-lifecycle.sh

# Explicit opt-in: a container with BPF/PERFMON/NET_ADMIN capabilities.
test-kernel: $(SKELETON)
	CC="$(CC)" bash tests/kernel-packets.sh

clean:
	rm -f $(BPF_OBJECT) $(SKELETON) $(OBJECT_DIGEST_HEADER) \
		$(LOADER_BINARY) $(VMLINUX) $(VMLINUX).tmp $(SKELETON).tmp \
		$(OBJECT_DIGEST_HEADER).tmp
	rmdir $(BUILD_DIR) 2>/dev/null || true
