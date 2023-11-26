# Makefile

SHELL = /bin/bash

# Define a name for the executable
PROJECT = rsadb_single_file_buffer_crypt_test

# Additional C/C++ libraries
CLIBS =

# Additional Fortran libraries
FLIBS = 

# Define macros for compiler and linker
CC = gcc
CPP = g++ 
LINKER = ld

# Define compiler and linker flags macros
CFLAGS := -v -Wall $(CFLAGS) -I../include -I./
FFLAGS := $(FFLAGS)
COMPILE_ONLY = -c
OUTPUT = -o
LFLAGS := $(LFLAGS)

# Build dependency rules
# ===============================================================
RSADB_SINGLE_FILE_BUFFER_CRYPT_TEST_DEPS = ../include/rsadb.h

RSADB_DEPS = ../include/rsadb.h
# ===============================================================

# Compile the files and build the executable
# ===============================================================
all:	$(PROJECT) 

rsadb_single_file_buffer_crypt_test.o:	rsadb_single_file_buffer_crypt_test.cpp $(RSADB_SINGLE_FILE_BUFFER_CRYPT_TEST_DEPS)
	$(CPP) $(COMPILE_ONLY) $(CFLAGS) rsadb_single_file_buffer_crypt_test.cpp

rsadb.o:	../src/rsadb.cpp $(RSADB_DEPS)
	$(CPP) $(COMPILE_ONLY) $(CFLAGS) ../src/rsadb.cpp

OBJS = rsadb.o rsadb_single_file_buffer_crypt_test.o

$(PROJECT):	$(OBJS)
	$(CPP) $(CFLAGS) $(OBJS) $(OUTPUT) $(PROJECT) $(LFLAGS) -lssl -lcrypto
# ===============================================================

# Install the new binaries
# ===============================================================
install:
	mkdir -p ../bin
	cp $(PROJECT) ../bin/$(PROJECT)
	chmod 755 ../bin/$(PROJECT)

# Remove object files and the executable after running make 
# ===============================================================
clean:
	echo Removing all OBJECT files from working directory...
	rm -f *.o 

	echo Removing EXECUTABLE file from working directory...
	rm -f $(PROJECT)

	echo Removing testfiles from working directory...
	rm -f *.pem

# End of makefile
