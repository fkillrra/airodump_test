all : airodump

airodump : main.o
	g++ -g -o airodump main.o -lpcap

main.o:
	g++ -std=c++11 -g -c -o main.o main.cpp

clean:
	rm -f airodump
	rm -f *.o

