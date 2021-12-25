obj-m := srtm_export.o

PWD := $(shell pwd)
KERNELDIR := /lib/modules/$(shell uname -r)/build
# EXTRA_CFLAGS= -O0

all:
	make -C $(KERNELDIR)  M=$(PWD) modules
clean:
	@echo "Cleaning up..."
	make -C $(KERNELDIR) M=$(PWD) clean
	@echo $(shell pwd)
