#!/bin/sh

DIR=/home/op/gitlab/twsz-openwrt-2.6.36/package/ezlink/ezwrt_api/files/

/bin/cp pengwifi.ko $DIR/lib/modules/
/bin/cp ../user/pwf $DIR/usr/sbin/
/bin/cp ../../libwebsockets/libwebsockets.so $DIR/usr/lib/
rm -rf /home/op/gitlab/twsz-openwrt-2.6.36/build_dir/target-mipsel_24kec+dsp_uClibc-0.9.33.2/ezwrt-api

