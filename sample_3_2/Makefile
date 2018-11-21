KDIR ?= /lib/modules/$(shell uname -r)/source
CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))

BIN := xdp_drop_kern.o xdp_drop_user
CLANG_FLAGS = -I. -I$(KDIR)/arch/$(ARCH)/include \
        -I$(KDIR)/arch/$(ARCH)/include/generated \
        -I$(KDIR)/include \
        -I$(KDIR)/arch/x86/include/uapi \
        -I$(KDIR)/arch/x86/include/generated/uapi \
        -I$(KDIR)/include/uapi \
        -I$(KDIR)/include/generated/uapi \
        -include $(KDIR)/include/linux/kconfig.h \
        -I$(KDIR)/tools/testing/selftests/bpf/ \
        -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
        -D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
        -Wno-gnu-variable-sized-type-not-at-end \
        -Wno-address-of-packed-member -Wno-tautological-compare \
        -Wno-unknown-warning-option  \
        -O2 -emit-llvm

CFLAGS = -I$(KDIR)/tools/lib/ -O2
BPFDIR := $(KDIR)/tools/lib/bpf/
BPFOBJ := $(BPFDIR)/libbpf.a
LDLIBS := -lelf

all: $(BIN)

%_kern.o: %_kern.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o - |      \
        $(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $@

xdp_drop_user: xdp_drop_user.c $(BPFOBJ)

$(BPFOBJ)::
	$(MAKE) -C $(BPFDIR) OUTPUT=$(BPFDIR)/

clean::
	$(RM) $(BIN)
