CC = g++

SRCS = antiscanner.cpp

PROG = antiscanner

CFLAGS = -g -l

LIBS = -lpcap

$(PROG) : $(SRCS)
	$(CC) $(SRCS) $(LIBS)

clean:
	rm -f *.o *~ $(PROG)