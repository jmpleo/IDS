# All Target
all:
	g++ -c -o sniffer.o main.cpp -std=c++14 
	g++ $(PCAPPP_LIBS_DIR) -o sniffer sniffer.o -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread -ldl -l:libpfring.a -lpq -lcurl 

# Clean Target 
clean:
	rm server.o
	rm sensor.o
	rm sensor
