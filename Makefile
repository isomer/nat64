CLANG?=clang
LLC?=llc
CFLAGS?=-O2 -g -D __BPF_TRACING__ -Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes


all: nat64.bpf.o nat64 nat64cli

#nat64: test_bpf.o test_case.o
nat64:
	true

nat64cli: LDLIBS=-lxdp -lbpf

all: $(TARGET)

%.bpf.o: BPF=1
%.bpf.o: %.c
	$(CLANG) -S \
		-target bpf \
		$(CFLAGS) \
		-D BPF=$(BPF) \
		-emit-llvm -c -o ${@:.o=.ll} $<
	$(LLC) -march bpf -filetype obj -o $@ ${@:.o=.ll}

clean:
	rm -f *.o *.ll nat64cli
