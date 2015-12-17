#export STAGING_DIR=/home/op/attitude_adjustment/staging_dir
#include ../env.mk
#include ../../../../libiwinfo/env.mk
include /home/op/shiyan/netlink/env.mk
CFLAGS=-Wall

all:
	${CC} ${CFLAGS} -I ../user/ -lpthread -o probe main.c nl.c probe.c ../user/util.c
	#${CC} ${CFLAGS} -L${STAGING_DIR}/target-mips_r2_uClibc-0.9.33.2/usr/lib/ -lcurl -lssl -lcrypto -lz -I${STAGING_DIR}/target-mips_r2_uClibc-0.9.33.2/usr/include/ -o a a.c
	${STRIP} probe

clean:
	rm -f probe

install:
	
