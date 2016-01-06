

AP200_DIR?=/home/op/domy-gigabit-ap-200/
DST_DIR:=${AP200_DIR}/progs.gpl/pengwifi/install/

all: lws kernel user probe
	echo "make all pengwifi"

lws:
	make -C libwebsockets

probe:
	make -C ap/probe

user: lws
	make -C ap/user

kernel:
	make -C ap/kernel

install:
	mkdir -p ${DST_DIR}/lib/modules/
	mkdir -p ${DST_DIR}/etc/init.d/
	mkdir -p ${DST_DIR}/usr/sbin/
	mkdir -p ${DST_DIR}/usr/lib/
	/bin/cp ap/kernel/pengwifi.ko ${DST_DIR}/lib/modules/
	/bin/cp ap/kernel/S50pengwifi.sh ${DST_DIR}/etc/init.d/
	/bin/cp ap/user/pwf ${DST_DIR}/usr/sbin/
	/bin/cp ap/probe/probe ${DST_DIR}/usr/sbin/
	/bin/cp libwebsockets/libwebsockets.so ${DST_DIR}/usr/lib/
	echo "Install pengwifi success!"


clean:
	make -C libwebsockets clean
	make -C ap/kernel clean
	make -C ap/user clean

