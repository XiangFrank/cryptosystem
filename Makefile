all:main

main:main.cpp util.h util.cpp
	g++ main.cpp util.h util.cpp -o c2 -static

clear:
	rm -f c2
