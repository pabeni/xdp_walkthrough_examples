KDIR ?= /lib/modules/$(shell uname -r)/source
CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))

BIN := xdp_dummy.o
CLANG_FLAGS = -I. -I$(KDIR)/arch/$(ARCH)/include \
        -I$(KDIR)/arch/$(ARCH)/include/generated \
        -I$(KDIR)/include \
        -I$(KDIR)/arch/$(ARCH)/include/uapi \
        -I$(KDIR)/arch/$(ARCH)/include/generated/uapi \
        -I$(KDIR)/include/uapi \
        -I$(KDIR)/include/generated/uapi \
        -I$(KDIR)/tools/testing/selftests/bpf/ \
        -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
        -D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
        -Wno-gnu-variable-sized-type-not-at-end \
        -Wno-address-of-packed-member -Wno-tautological-compare \
        -Wno-unknown-warning-option  \
        -O2 -emit-llvm

all: $(BIN)

%.o: %.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o - |      \
        $(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $@
