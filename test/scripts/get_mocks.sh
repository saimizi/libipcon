#!/usr/bin/bash

process_one_file() {
	local wrap_symbols=""

	for f in $1
	do
		wrap_symbols="${wrap_symbols},$(grep -o -e "\ __wrap.*(" $f | sed "s/(/,/" | sed "s/ //g" | sed "s/__/--/" | sed "s/_/=/" | tr -d '\n')"
	done

	echo $wrap_symbols | sed "s/^,//" | sed "s/,$//"
}

symbols=""


for f in $*
do
	if [ "x$symbols" = "x" ]; then
		symbols=$(process_one_file $f)
	else
		symbols="$symbols,$(process_one_file $f)"
	fi
done

#echo $symbols | tr -d '\n' > wrap_symbols.txt
echo $symbols | tr -d '\n'



