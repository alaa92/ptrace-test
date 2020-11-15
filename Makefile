CC=gcc
CXX=g++
ARCH=-m64
CFLAGS=-g $(ARCH) -Wall -Wextra -Wpedantic

test:
	$(CXX) $(CFLAGS) main.cpp -o main -ldl
	$(CC)  $(CFLAGS) -shared -fPIC lib.c -o libtest.so
	$(CXX) $(CFLAGS) target.cpp -o target
