BPF_MAKEFILE:="Makefile.bpf"

all: user_drop user_scramble

kern_drop_clean:
	-rm xdp_kern_drop.ll xdp_kern_drop.o

kern_drop:
	$(MAKE) -f $(BPF_MAKEFILE) xdp_kern_drop.o

kern_scramble_clean:
	-rm xdp_kern_scramble.ll xdp_kern_scramble.o

kern_scramble:
	$(MAKE) -f $(BPF_MAKEFILE) xdp_kern_scramble.o

user_drop_clean:
	-rm xdp_user_drop

user_drop:
	$(MAKE) -f $(BPF_MAKEFILE) xdp_user_drop

user_scramble_clean:
	-rm xdp_user_scramble

user_scramble:
	$(MAKE) -f $(BPF_MAKEFILE) xdp_user_scramble

clean: user_drop_clean user_scramble_clean

fmt:
	-clang-format -i *.h
	-clang-format -i *.c
	black ape.py


.PHONY: user_drop_clean kern_drop_clean user_drop kern_drop kern_scramble_clean kern_scramble
