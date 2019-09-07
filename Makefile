BPF_MAKEFILE:="Makefile.bpf"

all:
	$(MAKE) user_drop
	$(MAKE) user_scramble
	$(MAKE) user_reflect

kern_drop_clean:
	-rm xdp_kern_drop.ll xdp_kern_drop.o

kern_drop:
	$(MAKE) -f $(BPF_MAKEFILE) xdp_kern_drop.o

kern_reflect_clean:
	-rm xdp_kern_reflect.ll xdp_kern_reflect.o

kern_reflect:
	$(MAKE) -f $(BPF_MAKEFILE) xdp_kern_reflect.o

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

user_reflect_clean:
	-rm xdp_user_reflect

user_reflect:
	$(MAKE) -f $(BPF_MAKEFILE) xdp_user_reflect

clean:
	$(MAKE) user_drop_clean
	$(MAKE) user_scramble_clean
	$(MAKE) user_reflect_clean

fmt:
	-clang-format -i *.h
	-clang-format -i *.c
	black ape.py


.PHONY: user_drop_clean kern_drop_clean user_drop kern_drop kern_scramble_clean kern_scramble kern_reflect_clean kern_reflect user_reflect_clean user_reflect
