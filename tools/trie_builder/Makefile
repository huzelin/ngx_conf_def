#Macros
INCLUDE = -I .
LIBPATH = -lpthread -lm -lrt -lcrypto -lssl -lidn 
DEBUG_DEF = -g -O2

CFLAGS = $(INCLUDE) -g
TOOLS = TrieBuilder

#Actions
all : clean $(LIB) $(TOOLS)

clean : 
	rm -r -f *.o $(LIB) $(TOOLS)

TrieBuilder : TrieBuilder.o
	g++ $(CFLAGS) -o $@ $^ $(LIBPATH) 
.o : .cpp
	g++ -c $^ ${CFLAGS} -o $@
