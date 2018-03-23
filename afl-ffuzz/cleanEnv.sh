#!/bin/bash
# Prepare a clean environment for afl
total=$(ipcs -m | awk 'END{print NR}') 
_index=4
while [ $_index -lt $total ]
do
	shmid=$(ipcs -m | sed -n ''$_index'p' | awk '{print $2}')
	size=$(ipcs -m | sed -n ''$_index'p' | awk '{print $5}')
	if [ $size = 65536 ]
	then
		echo '--------------'
		echo "shmid=$shmid, size=$size"
		echo `ipcrm -m  $shmid`
	fi
	_index=`expr $_index + 1`;
done

qemu_total=$(ps -A | grep qemu | awk 'END{print NR}')
qemu_total=`expr $qemu_total + 1`;
index=1
while [ $index -lt $qemu_total ]
do
	qemuPid=$(ps -A | grep qemu | sed -n ''$index'p' | awk 'END{print $1}')
	echo $yourpass | sudo -S kill -s SIGKILL $qemuPid
	index=`expr $index + 1`;	
done


mkdir /tmp/afltestcase
mkdir /tmp/afltracebits

rm -rf /tmp/afltestcase/*
rm -rf /tmp/afltracebits/*

rm -f /tmp/afl_qemu_queue

rm -rf /home/binzhang/EPFL/testfolder/output/*
rm -rf /home/binzhang/EPFL/testfolder/input/*

echo a > /home/binzhang/EPFL/testfolder/input/aa

echo bb > /home/binzhang/EPFL/testfolder/input/bb

