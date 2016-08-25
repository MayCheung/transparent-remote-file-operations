all: mylib.so server

server.o: server.c
	gcc -g -O0 -I ../include -Wall -c  server.c   

server: server.o
	gcc  -L../lib -ldirtree -Wall -o server server.o 

mylib.o: mylib.c
	gcc -g -O0 -I../include -Wall -fPIC -DPIC -c mylib.c

mylib.so: mylib.o
	ld -L../lib -shared -o mylib.so mylib.o -ldl

clean:
	rm -f server *.o *.so
