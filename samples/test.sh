#!/bin/sh
#
# This file is part of Libipcon
# Copyright (C) 2017-2025 Seimizu Joukan
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Lesser General Public License for more details.
#




run() {
	MAX_CNT=$2

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

run ipcon_user 1
run ipcon_sender 50



