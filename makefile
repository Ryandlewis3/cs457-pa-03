all:
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -l:libcrypto.so.1.1
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -l:libcrypto.so.1.1
	gcc wrappers.c     dispatcher.c -o dispatcher

clean:
	rm -f dispatcher amal/amal amal/logAmal.txt basim/basim basim/logBasim.txt bunnyCopy.mp4 
