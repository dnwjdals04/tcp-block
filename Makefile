LDLIBS=-lpcap

all: tcp-block

main.o: main.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

iphdr.o: iphdr.h iphdr.cpp

ip.o: ip.h ip.cpp

mac.o: mac.h mac.cpp

tcp-block: main.o ip.o mac.o iphdr.o ethhdr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o
