all:
	gcc -o pgen *.c
debug:
	gcc -g -o pgen *.c
clean:
	rm -rf tags cscope.out pgen *.o
