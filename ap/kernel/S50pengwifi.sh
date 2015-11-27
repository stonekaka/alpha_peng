#!/bin/sh
case $1 in
start)
#	rmmod pengwifi
	rgdb -s /wlan/inf:2/enable 0
	/etc/scripts/misc/profile.sh put;submit WLAN
	insmod /lib/modules/pengwifi.ko	
	sleep 1
	killall pwf
	pwf -r 60.206.36.144 -f &
	;;
stop)
	killall pwf && rmmod pengwifi
	;;
restart)
	sleep 3
	$0 stop
	$0 start
	;;
esac
