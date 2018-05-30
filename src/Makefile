
ROOT=..
INCLUDE=-I$(ROOT)/inc -I$(ROOT)/net/inc -I$(ROOT)/ipq/inc -I$(ROOT)/mem/inc
OUTPUT=$(ROOT)/bin
LIBRARIES=$(OUTPUT)/pxsock.o $(OUTPUT)/pxmem.o $(OUTPUT)/libpxipq.a -lipq -lboost_regex

default: wall 
wall:webwd.cpp
	g++ $(INCLUDE) -g webwd.cpp $(LIBRARIES) -o $(OUTPUT)/tnswd
clean:
	rm -f $(OUTPUT)/tnswd
	
