#!/bin/sh

#DIR=/home/op/gitlab/twsz-openwrt-2.6.36/package/ezlink/ezwrt_api/files/
DIR=/home/op/domy-gigabit-ap-200/progs.gpl/pengwifi/install

mkdir -p $DIR/lib/modules/
mkdir -p $DIR/etc/init.d/
mkdir -p $DIR/usr/sbin/
mkdir -p $DIR/usr/lib/

/bin/cp pengwifi.ko $DIR/lib/modules/
/bin/cp pengwifi $DIR/etc/init.d/
/bin/cp ../user/pwf $DIR/usr/sbin/
/bin/cp ../../libwebsockets/libwebsockets.so $DIR/usr/lib/

