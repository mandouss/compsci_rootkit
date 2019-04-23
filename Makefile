ifeq ($(KERNELRELEASE),)  

KERNELDIR ?= /lib/modules/$(shell uname -r)/build 
PWD := $(shell pwd)  

.PHONY: build clean  

build: secure_process 
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules  

secure_process:
	gcc -Wall -Werror -g -o secure_process secure_process.c

clean:
	rm -rf *.o *~ core .depend .*.cmd *.order *.symvers *.ko *.mod.c secure_process secure_mod
else  

$(info Building with KERNELRELEASE = ${KERNELRELEASE}) 
obj-m :=    secure_mod.o  

endif
