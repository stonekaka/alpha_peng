#!/bin/sh
case $1 in
start)
#	rmmod pengwifi
	rgdb -s /wan/rg/inf:1/mode 2
	/etc/scripts/misc/profile.sh put;submit WAN
	ifconfig br0:1 192.168.0.50/24
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
