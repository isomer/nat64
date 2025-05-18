CLANG?=clang
LLC?=llc

all: nat64.o

%.o: %.c
	$(CLANG) -S \
		-target bpf \
		-D __BPF_TRACING__ \
		-Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes \
		-O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march bpf -filetype obj -o $@ ${@:.o=.ll}

clean:
	rm -f *.o *.ll
