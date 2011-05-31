CC = g++

SRCS = antiscanner.cpp

PROG = antiscanner

CFLAGS = -o $(PROG)

LIBS = -lpcap

$(PROG) : $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) $(LIBS)

clean:
	rm -f *.o *~ $(PROG)