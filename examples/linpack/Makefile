# Note: elfconv cannot compile the linpack binary now

CC=clang-16

linpack-soft-float: nostdin_linpack.c
	$(CC) -static nostdin_linpack.c -o a.soft-float.out

linpack: nostdin_linpack.c
	$(CC) -static nostdin_linpack.c -o a.out

clean:
	rm *.out
