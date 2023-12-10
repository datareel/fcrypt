# Makefile

SHELL = /bin/bash

# Define a name for the executable
PROJECT = smartcard_encrypt_test

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
SMARTCARD_ENCRYPT_TEST_DEPS = ../include/smart_card.h

SMART_CARD_DEPS = ../include/smart_card.h
# ===============================================================

# Compile the files and build the executable
# ===============================================================
all:	$(PROJECT) 

smartcard_encrypt_test.o:	smartcard_encrypt_test.cpp $(SMARTCARD_ENCRYPT_TEST_DEPS)
	$(CPP) $(COMPILE_ONLY) $(CFLAGS) smartcard_encrypt_test.cpp

smart_card.o:	../src/smart_card.cpp $(SMART_CARD_DEPS)
	$(CPP) $(COMPILE_ONLY) $(CFLAGS) ../src/smart_card.cpp

OBJS = smart_card.o smartcard_encrypt_test.o

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
