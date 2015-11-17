
#include /home/op/shiyan/netlink/kernel/../env.mk
#include /home/op/gitlab/ezlink_api/build_patch/env.mk
include /home/op/pengwifi/libwebsockets/env.mk.dm202

pengwifi-objs = ker.o table.o pengwifi_proc.o acl.o

obj-m := pengwifi.o

default:
	make -C $(KERNEL_DIR) M=$(shell pwd) CROSS_COMPILE=$(CROSS_COMPILE)

clean:
	rm -rf *.o *.ko *.mod.c .*.cmd *.markers *.order *.symvers .tmp_versions	
