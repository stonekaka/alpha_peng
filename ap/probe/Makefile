#export STAGING_DIR=/home/op/attitude_adjustment/staging_dir
#include ../env.mk
#include ../../../../libiwinfo/env.mk
include /home/op/pengwifi/libwebsockets/env.mk.ap200
#include /home/op/shiyan/netlink/env.mk
CFLAGS+=-Wall -D_GNU_SOURCE

all:
	${CC} ${CFLAGS} -I${INCLUDE_DIR} -I../user/ -lpthread -o probe main.c nl.c probe.c pdu.c udp.c ../user/util.c
#	${CC} ${CFLAGS} -L${STAGING_DIR}/target-mips_r2_uClibc-0.9.33.2/usr/lib/ -lcurl -lssl -lcrypto -lz -I${STAGING_DIR}/target-mips_r2_uClibc-0.9.33.2/usr/include/ -o a a.c
	${STRIP} probe

clean:
	rm -f probe

install:
	
