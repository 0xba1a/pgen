all:
	gcc -Wall -o pgen *.c
debug:
	gcc -Wall -g -o pgen *.c
clean:
	rm -rf tags cscope.out pgen *.o
