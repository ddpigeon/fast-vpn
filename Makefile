all:
	g++ client.cpp -lsodium -o client
	g++ server.cpp -lsodium -o server
