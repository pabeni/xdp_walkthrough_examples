CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))

BIN := xdp_vxlan_kern.o xdp_vxlan_user
CLANG_FLAGS = -I. \
        -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
        -D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
        -Wno-gnu-variable-sized-type-not-at-end \
        -Wno-address-of-packed-member -Wno-tautological-compare \
        -Wno-unknown-warning-option  \
        -O2 -emit-llvm

LDLIBS := -lelf -lbpf

all: $(BIN)

%_kern.o: %_kern.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o - |      \
        $(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $@

xdp_drop_user: xdp_drop_user.c

clean::
	$(RM) $(BIN)
