#!/bin/bash
echo
echo "Script to Test PA-03"
echo "By: Mohamed Aboutabl"
echo

rm -f dispatcher amal/amal amal/logAmal.txt basim/basim basim/logBasim.txt basim/bunny.rcvd 
rm -f bunny.mp4
ln -s  ../bunny.mp4       bunny.mp4

gcc wrappers.c     dispatcher.c -o dispatcher

echo "=============================="
echo "Testing STUDENT's Amal source against ABOUTABL's Basim"
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -l:libcrypto.so.1.1
	cp  basim_aboutablExecutable     basim/basim

echo "=============================="
echo "Starting the dispatcher"
./dispatcher

echo
echo "======  Amal's  LOG  ========="
cat amal/logAmal.txt

echo
echo "======  Basim's  LOG  ========="
cat basim/logBasim.txt
echo
echo

echo "comment out the following exit only after your Amal passes above test"
exit 0

echo "=============================="
echo "Testing STUDENT's Basim source against ABOUTABL's Amal"
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -l:libcrypto.so.1.1
	cp  amal_aboutablExecutable     amal/amal

echo "=============================="
echo "Starting the dispatcher"
./dispatcher

echo
echo "======  Amal's  LOG  ========="
cat amal/logAmal.txt

echo
echo "======  Basim's  LOG  ========="
cat basim/logBasim.txt
echo
echo



echo "comment out the following exit only after your Basim passes above test"
exit 0


echo "=============================="
echo "Testing STUDENT's Amal  & Basim source against each other"
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -l:libcrypto.so.1.1
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -l:libcrypto.so.1.1

echo "=============================="
echo "Starting the dispatcher"
./dispatcher

echo
echo "======  Amal's  LOG  ========="
cat amal/logAmal.txt

echo
echo "======  Basim's  LOG  ========="
cat basim/logBasim.txt
echo
echo
