obj-m := srtm.o
# srtm-objs := srtm.o cJSON/cJSON.o
# ccflags-y := -I$(shell pwd)/cJSON/

PWD := $(shell pwd)
KERNELDIR := /lib/modules/$(shell uname -r)/build
EXTRA_CFLAGS= -O0
CC = gcc

all:
	make -C $(KERNELDIR)  M=$(PWD) modules
clean:
	@echo "Cleaning up..."
	make -C $(KERNELDIR) M=$(PWD) clean
	@echo $(shell pwd)
json:
	${CC} point_test.c jsmn/jsmn.h -lm -o point_test
jsmna:
	${CC} point_test.c -o point_test
