CLANG?=clang
LLC?=llc
CFLAGS?=-O2 -g -D __BPF_TRACING__

all: nat64.o

%.o: %.c
	$(CLANG) -S \
		-target bpf \
		$(CFLAGS) \
		-Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes \
		-emit-llvm -c -o ${@:.o=.ll} $<
	$(LLC) -march bpf -filetype obj -o $@ ${@:.o=.ll}

clean:
	rm -f *.o *.ll
