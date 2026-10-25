#######################
#### Start of File ####
#######################
# --------------------------------------------------------------- 
# Makefile Contents: Makefile for command line builds
# C/C++ Compiler Used: g++ (GCC) 14.3.1 20251022 (Red Hat 14.3.1-4)
# --------------------------------------------------------------- 
# Define a name for the executable
PROJECT = fcrypt

include linux.env

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
