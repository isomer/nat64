CLANG?=clang
LLC?=llc
CFLAGS?=-O2 -g -D __BPF_TRACING__

ifdef TEST
TARGET=nat64
CFLAGS:=$(CFLAGS) -D TEST=1

nat64: nat64.o test_bpf.o test_case.o

else
TARGET=nat64.o
endif

all: $(TARGET)

ifndef TEST
%.o: %.c
	$(CLANG) -S \
		-target bpf \
		$(CFLAGS) \
		-Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes \
		-emit-llvm -c -o ${@:.o=.ll} $<
	$(LLC) -march bpf -filetype obj -o $@ ${@:.o=.ll}
endif

clean:
	rm -f *.o *.ll
