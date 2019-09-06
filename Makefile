BPF_MAKEFILE:="Makefile.bpf"

kern_clean:
	-rm xdp_kern_drop.ll
	-rm xdp_kern_drop.o

kern_drop:
	$(MAKE) -f $(BPF_MAKEFILE) xdp_kern_drop.o

all: user

user_clean:
	-rm xdp_user_drop

user:
	$(MAKE) -f $(BPF_MAKEFILE) xdp_user_drop

fmt:
	-clang-format -i *.h
	-clang-format -i *.c
	black ape.py


.PHONY: user_clean kern_clean user kern
