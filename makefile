#Borrar todos los .o con $make clean

main: main.o king.o
	gcc -g -w -o  main main.o king.o `gpgme-config --cflags --libs`

main.o: main.c king.c sockets.h
	gcc -c -g -w main.c

king.o: king.c king.h
	gcc -c -g -w king.c
clean: 
	rm main.o king.o