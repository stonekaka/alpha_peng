#include env.mk
include ./env.mk
CFLAGS=-O2 -fPIC -Wall -I$(INCLUDE_DIR) -DLWS_NO_EXTENSIONS
CFLAGS+=#-DHAVE_GETIFADDRS
CFLAGS+=-I$(TOP_DIR)/progs.gpl/openssl-0.9.8za/include/
LDFLAGS+=-L$(TOP_DIR)/progs.gpl/openssl-0.9.8za/
SOFLAGS=-O2 -fPIC -shared
TARGET=libwebsockets.so
FILES=$(wildcard *.c)
OBJS=$(patsubst %c,%o,$(FILES))	


.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(SOFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	$(RM) $(TARGET)
	$(RM) $(OBJS)

