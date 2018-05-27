obj-m := arp.o

KVERSION := $(shell uname -r)
KERNELDIR := /lib/modules/$(KVERSION)/build

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
