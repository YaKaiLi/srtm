KERNEL_SOURCE := /lib/modules/$(shell uname -r)/build/
PWD := $(shell pwd)
obj-m := srtm.o
# ccflags-y += -Wextra

default:
	${MAKE} -C ${KERNEL_SOURCE} M=${PWD} modules

clean:
	${MAKE} -C ${KERNEL_SOURCE} M=${PWD} clean
