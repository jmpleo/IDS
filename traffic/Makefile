# All Target
all:
#	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o sensor.o sensor.cpp -std=c++14
#	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o sensor sensor.o -lpfring $(PCAPPP_LIBS) -lpq -lpcap -pthread -lpfring -lamqpcpp -lpthread -levent -ldl -I/usr/include/mysql -lmysqlclient 
	g++ -c -o sniffer.o main.cpp 
	g++ $(PCAPPP_LIBS_DIR)  -static-libstdc++ -o sniffer sniffer.o -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread -ldl -l:libpfring.a -lpq -lcurl
#	g++ -c -o server.o server.cpp 
#	g++ -o server server.o -I/usr/include/mysql -I/usr/include/boost -lmysqlclient -lpthread -pthread -lboost_thread -lncurses -lcrypt -lPocoNet -lPocoFoundation -lamqpcpp -I/usr/local/Poco -lpthread -levent -ldl
#	g++ -c -o view.o view.cpp 
#	g++ -o view view.o -I/usr/include/mysql -lmysqlclient -I/usr/include/graphviz -lgvc -lcgraph
# Clean Target 
clean:
	rm server.o
	rm sensor.o
	rm sensor
