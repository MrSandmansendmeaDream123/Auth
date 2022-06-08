#g++ -o webserver webserver.cpp -lcleansocks -lcleantlsc -lssl
#OBJS specifies which files to compile as part of the project

OBJS =	webserver.cpp 

#CC specifics compiler 
CC = g++

#LINKER_FLAGS for libraies linked
LINKER_FLAGS =	-lcleansocks -lcleantlsc -lssl

#OBJ_NAME name of exe
OBJ_NAME =	webserver

#Target that compilwa executable
all: $(OBJS)
	$(CC) -o $(OBJ_NAME) $(OBJS) $(LINKER_FLAGS)