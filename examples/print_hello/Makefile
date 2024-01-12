CC=clang-16

print_hello: print_hello.c start.s
	$(CC) -nostdlib -static print_hello.c start.s

clean:
	rm a.out
