#######################
#### Start of File ####
#######################
# --------------------------------------------------------------- 
# Makefile Contents: Makefile for statically linked command line builds
# C/C++ Compiler Used: g++ (GCC) 8.5.0 20210514 (Red Hat 8.5.0-18)
# --------------------------------------------------------------- 
# Define a name for the executable
PROJECT = fcrypt

# Setup my path to the DataReel library
GCODE_LIB_DIR = ../../3plibs/datareel

GCODE_INCLUDE_PATH = $(GCODE_LIB_DIR)/include
OBJ_EXT = .o
PATHSEP = /

ADD_INC_PATHS = -I$(GCODE_INCLUDE_PATH) -I../include -I../../include

# Define debug macros specific to the gxcode library
64BIT_DEFMACS = -D__64_BIT_DATABASE_ENGINE__ -D_LARGEFILE64_SOURCE
ANSI_DEFMACS = -D__USE_ANSI_CPP__
CPP_DEFMACS = -D__USE_CPP_IOSTREAM__ -D__CPP_EXCEPTIONS__
DISPLAY_DEFMACS = -D__CONSOLE__
THREAD_DEFMACS = -D__REENTRANT__ 
POSIX_DEFMACS= -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS
UNICODE_DEMACS = -D__HAS_UNICODE__
#SMARTCARD_DEMACS = -D__ENABLE_SMART_CARD__ -D__RHEL6__
#SMARTCARD_DEMACS = -D__ENABLE_SMART_CARD__ -D__RHEL7__
SMARTCARD_DEMACS = -D__ENABLE_SMART_CARD__ -D__RHEL8__
#SMARTCARD_DEMACS = -D__ENABLE_SMART_CARD__ -D__RHEL9__

# Setup define macros
DEFMACS = -D__UNIX__ -D__POSIX__ -D__LINUX__ -D__X86__ \
$(64BIT_DEFMACS) $(ANSI_DEFMACS) $(BTREE_DEFMACS) $(CPP_DEFMACS) \
$(DATABASE_DEFMACS) $(DEBUG_DEFMACS) $(DEVCACHE_DEFMACS) $(DISPLAY_DEFMACS) \
$(FILESYS_DEFMACS) $(TESTCODE_DEFMACS) $(PS_DEFMACS) $(HTM_DEFMACS) \
$(TXT_DEFMACS) $(IO_DEFMACS) $(THREAD_DEFMACS) $(POSIX_DEFMACS) \
$(UNICODE_DEMACS) $(SMARTCARD_DEMACS)

# Define macros for compiler and linker
CC = gcc
CPP = g++ 
LINKER = ld

# Define compiler and linker flags macros
COMPILE_FLAGS= -Wall $(ADD_INC_PATHS) $(DEFMACS) -fpermissive
COMPILE_ONLY = -c
OUTPUT = -o
LINKER_FLAGS = -lpthread -lm -lssl -lcrypto

# Set the project dependencies  
# ===============================================================
include $(GCODE_LIB_DIR)/env/glibdeps.mak
# ===============================================================

# Compile the files and build the executable
# ===============================================================
all:	$(PROJECT)$(EXE_EXT)

include $(GCODE_LIB_DIR)/env/glibobjs.mak
include ../project.mak

$(PROJECT):	$(OBJECTS)
	$(CPP) $(COMPILE_FLAGS) $(OBJECTS) $(OUTPUT) $(PROJECT) $(LINKER_FLAGS)
# ===============================================================

# Remove object files and the executable after running make 
# ===============================================================
clean:
	echo Removing all OBJECT files from working directory...
	rm -f *.o 

	echo Removing EXECUTABLE file from working directory...
	rm -f $(PROJECT)
# --------------------------------------------------------------- 
#####################
#### End of File ####
#####################
