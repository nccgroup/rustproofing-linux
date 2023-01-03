# SPDX-License-Identifier: GPL-2.0

ifeq ($(KDIR),)
$(error "Please use: make LLVM=1 KDIR=path/to/built/kernel/")
endif

default:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
