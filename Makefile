BPF_MAKEFILE:="Makefile.bpf"

all:
	$(MAKE) user_drop
	$(MAKE) user_scramble
	$(MAKE) user_mirror

kern_drop_clean:
	-rm xdp_kern_drop.ll xdp_kern_drop.o

kern_drop:
	$(MAKE) -f $(BPF_MAKEFILE) xdp_kern_drop.o

kern_mirror_clean:
	-rm xdp_kern_mirror.ll xdp_kern_mirror.o

kern_mirror:
	$(MAKE) -f $(BPF_MAKEFILE) xdp_kern_mirror.o

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

user_mirror_clean:
	-rm xdp_user_mirror

user_mirror:
	$(MAKE) -f $(BPF_MAKEFILE) xdp_user_mirror

clean:
	$(MAKE) user_drop_clean
	$(MAKE) user_scramble_clean
	$(MAKE) user_mirror_clean

fmt:
	-clang-format -i *.h
	-clang-format -i *.c
	black ape.py


.PHONY: user_drop_clean kern_drop_clean user_drop kern_drop kern_scramble_clean kern_scramble kern_mirror_clean kern_mirror user_mirror_clean user_mirror
