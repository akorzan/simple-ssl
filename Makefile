default:
	gcc -o server server.c -lssl -lcrypto -Wall
	gcc -o client client.c -lssl -lcrypto -Wall

clean:
	-rm server client
