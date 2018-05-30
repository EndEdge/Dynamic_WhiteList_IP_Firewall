# Makefile for ipq module
ROOT=.
INCLUDE=-I$(ROOT)/inc -I../mem/inc -I../utils/ -I../tns/
OBJ=../bin
LIBRARIES=
SRC=$(ROOT)/src

default: ipq

ipq: ipq_0 ipq_1
	ar r $(OBJ)/libpxipq.a $(OBJ)/ipq_wrapper.o $(OBJ)/ipq_filter.o 

ipq_0: $(SRC)/ipq_wrapper.cpp
	g++ $(INCLUDE) -g -c $(SRC)/ipq_wrapper.cpp $(LIBRARIES) -o $(OBJ)/ipq_wrapper.o

ipq_1: $(SRC)/ipq_filter.cpp
	g++ $(INCLUDE) -g -c $(SRC)/ipq_filter.cpp $(LIBRARIES) -o $(OBJ)/ipq_filter.o

clean:
	rm -f $(OBJ)/ipq_wrapper.o
	rm -f $(OBJ)/ipq_filter.o
	rm -f $(OBJ)/libpxipq.a

