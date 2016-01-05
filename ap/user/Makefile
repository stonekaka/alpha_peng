#export STAGING_DIR=/home/op/attitude_adjustment/staging_dir
#include ../../../../libwebsockets/env.mk
#include /home/op/gitlab/ezlink_api/build_patch/env.mk
include /home/op/pengwifi/libwebsockets/env.mk.ap200
CFLAGS+=-Wall -pthread -DUSE_OPENSSL
CFLAGS+=-I../../libwebsockets/
LIB_DIR+=-L../../libwebsockets/

AP200_XML=1
ifeq ($(AP200_XML), 1)
XML_SRC=$(TOP_DIR)/comlib/libxmldbc.c
CFLAGS+= -DAP200_XML
CFLAGS += -I$(TOP_DIR)/include
endif

all:
#	${CC} ${CFLAGS} -o nlcli cli.c
	${CC} ${CFLAGS} -I${INCLUDE_DIR} -DLWS_NO_EXTENSIONS -L${LIB_DIR} -L. -Wl,-rpath=${LIB_DIR} -lwebsockets -lssl -lcrypto -lpthread -lcurl -lm -o pwf main.c cJSON.c nl.c list.c handle_recv.c util.c curl_util.c base64.c platform.c httpserver.c discovery.c log.c urlcode.c ${XML_SRC}
#	${CC} ${CFLAGS} -DLWS_NO_EXTENSIONS -L${LIB_DIR} -L. -lwebsockets -lssl -lcrypto -I${INCLUDE_DIR} -I../../../../libwebsockets/ -o tp test-ping.c

clean:
	rm -rf pwf  *.o
