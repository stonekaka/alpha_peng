#export STAGING_DIR=/home/op/attitude_adjustment/staging_dir
#include ../env.mk
include ../../../../libiwinfo/env.mk
CFLAGS=-Wall

all:
	${CC} ${CFLAGS} -o cli cli.c
	${CC} ${CFLAGS} -o up up.c
	#${CC} ${CFLAGS} -L${STAGING_DIR}/target-mips_r2_uClibc-0.9.33.2/usr/lib/ -lcurl -lssl -lcrypto -lz -I${STAGING_DIR}/target-mips_r2_uClibc-0.9.33.2/usr/include/ -o a a.c
	${STRIP} cli

clean:
	rm -f dmhandle dmmon dmwatch

install:
	cp -rf dmhandle ${ROOTFS}/ezwrt
	cp -rf dmmon ${ROOTFS}/ezwrt
	cp -rf dmwatch ${ROOTFS}/ezwrt
