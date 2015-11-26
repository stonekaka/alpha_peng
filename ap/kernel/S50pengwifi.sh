#!/bin/sh
case $1 in
start)
	rmmod pengwifi
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

