all:
	g++ src/client.cpp -lsodium -o client
	g++ src/server.cpp -lsodium -o server
