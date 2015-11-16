#export STAGING_DIR=/home/op/attitude_adjustment/staging_dir
#include ../../../../libwebsockets/env.mk
include /home/op/gitlab/ezlink_api/build_patch/env.mk
CFLAGS+=-Wall

all:
#	${CC} ${CFLAGS} -o nlcli cli.c
	${CC} ${CFLAGS} -DLWS_NO_EXTENSIONS -L${LIB_DIR} -L. -Wl,-rpath=${LIB_DIR} -lwebsockets -lssl -lcrypto -lpthread -lcurl -lm -I${INCLUDE_DIR} -I../../../../libwebsockets/ -o pwf main.c cJSON.c nl.c list.c handle_recv.c util.c base64.c platform.c httpserver.c discovery.c log.c
#	${CC} ${CFLAGS} -DLWS_NO_EXTENSIONS -L${LIB_DIR} -L. -lwebsockets -lssl -lcrypto -I${INCLUDE_DIR} -I../../../../libwebsockets/ -o tp test-ping.c

clean:
	rm -rf pwf 
