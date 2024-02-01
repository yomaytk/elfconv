CXX=clang++-16
INCLUDE=

test: test.cpp Loader.cpp
	g++ $(INCLUDE) -c Loader.cpp -o loader.o
	g++ $(INCLUDE) -c test.cpp -o test.o
	g++ test.o loader.o -o test -lbfd -lelf

clean:
	rm *.o test
