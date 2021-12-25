KERNEL_SOURCE := /lib/modules/$(shell uname -r)/build/
PWD := $(shell pwd)
obj-m := srtm_dev.o

default:
	${MAKE} -C ${KERNEL_SOURCE} M=${PWD} modules

clean:
	${MAKE} -C ${KERNEL_SOURCE} M=${PWD} clean

user:
	gcc c_call_ioctl.c -o c_call_ioctl
