# ape - an XDP packet manipulation tool

Ape is a tool to manipulate UDP packets. For now, it can drop UDP packets - all UDP traffic, or specify `-udpPort` - from an interface with a given desired % to drop.

The learning resources I used to create this project is https://github.com/xdp-project/xdp-tutorial, and I include it as a submodule to the use the Makefile plumbing (and borrow a lot of the code).
