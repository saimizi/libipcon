#!/bin/sh


run() {
	MAX_CNT=100

	cnt=0
	while [ 1 ];
	do
		if [ $cnt -ge $MAX_CNT ];then
			break;
		fi

		if [ "$1" = "ipcon_user" ];then
			$1 &
		fi

		if [ "$1" = "ipcon_sender" ];then
			$1 "Sender_${cnt}" 1>/dev/null 2>&1 &
		fi

		if [ $? -ne 0 ];then
			break;
		fi

		cnt=`expr $cnt + 1`
	done
}

run ipcon_user
run ipcon_sender



