CC=clang-16

hello: hello.c
	$(CC) -static -o hello hello.c; \
	strip hello -o hello_stripped; \

clean:
	rm hello hello_stripped
