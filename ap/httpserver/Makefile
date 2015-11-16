#export STAGING_DIR=/home/op/attitude_adjustment/staging_dir
#include /home/op/shiyan/netlink/kernel/../env.mk
include /home/op/pengwifi/libwebsockets/env.mk
#CFLAGS=-Wall

all:
	${CC} ${CFLAGS} -o httpserver httpserver.c ../user/util.c

clean:
	rm -f httpserver

