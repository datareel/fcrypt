# Include file used for all project makefiles
# ===============================================================
APPINC_PATH = ../../include/
APPSRC_PATH = ../../src/

# Build dependency rules
# ===============================================================
CRYPTDB_DEP = $(APPINC_PATH)cryptdb.h $(APPINC_PATH)aesdb.h

AESDB_DEP = $(APPINC_PATH)aesdb.h

RSADB_DEP = $(APPINC_PATH)rsadb.h

SMART_CARD_DEP = $(APPINC_PATH)smart_card.h

GLOBALS_DEP = $(APPINC_PATH)globals.h

C_CONFIG_DEP = $(APPINC_PATH)c_config.h $(APPINC_PATH)globals.h \
	$(APPINC_PATH)c_thread.h

C_THREAD_DEP = $(APPINC_PATH)c_thread.h $(APPINC_PATH)globals.h \
	$(APPINC_PATH)c_config.h $(APPINC_PATH)aesdb.h $(APPINC_PATH)cryptdb.h \
	$(APPINC_PATH)rsadb.h $(APPINC_PATH)smart_card.h

PROJECT_DEP = $(C_THREAD_DEP) ../fcrypt.h
# ===============================================================

cryptdb$(OBJ_EXT):	$(APPSRC_PATH)cryptdb.cpp $(CRYPTDB_DEP)
	$(CPP) $(COMPILE_ONLY) $(COMPILE_FLAGS) $(APPSRC_PATH)cryptdb.cpp

aesdb$(OBJ_EXT):	$(APPSRC_PATH)aesdb.cpp $(AESDB_DEP)
	$(CPP) $(COMPILE_ONLY) $(COMPILE_FLAGS) $(APPSRC_PATH)aesdb.cpp

rsadb$(OBJ_EXT):	$(APPSRC_PATH)rsadb.cpp $(RSADB_DEP)
	$(CPP) $(COMPILE_ONLY) $(COMPILE_FLAGS) $(APPSRC_PATH)rsadb.cpp

smart_card$(OBJ_EXT):	$(APPSRC_PATH)smart_card.cpp $(SMART_CARD_DEP)
	$(CPP) $(COMPILE_ONLY) $(COMPILE_FLAGS) $(APPSRC_PATH)smart_card.cpp

globals$(OBJ_EXT):	$(APPSRC_PATH)globals.cpp $(GLOBALS_DEP)
	$(CPP) $(COMPILE_ONLY) $(COMPILE_FLAGS) $(APPSRC_PATH)globals.cpp

c_config$(OBJ_EXT):	$(APPSRC_PATH)c_config.cpp $(C_CONFIG_DEP)
	$(CPP) $(COMPILE_ONLY) $(COMPILE_FLAGS) $(APPSRC_PATH)c_config.cpp

c_thread$(OBJ_EXT):	$(APPSRC_PATH)c_thread.cpp $(C_THREAD_DEP)
	$(CPP) $(COMPILE_ONLY) $(COMPILE_FLAGS) $(APPSRC_PATH)c_thread.cpp

# Rules used to build project modules
$(PROJECT)$(OBJ_EXT):	../$(PROJECT).cpp $(PROJECT_DEP)
	$(CPP) $(COMPILE_ONLY) $(COMPILE_FLAGS) ../$(PROJECT).cpp

# DLL entry point objects
GLIB_DLL_OBJECTS = stdafx$(OBJ_EXT) \
	gxdlcode$(OBJ_EXT)

# Core database library components
GLIB_DATABASE_CORE_OBJECTS =  gxint32$(OBJ_EXT) \
	gxint64$(OBJ_EXT) \
	gxuint32$(OBJ_EXT) \
	gxuint64$(OBJ_EXT) \
	gxcrc32$(OBJ_EXT) \
	gxdbase$(OBJ_EXT) \
	gxderror$(OBJ_EXT) \
	gxdfp64$(OBJ_EXT) \
	gxdfptr$(OBJ_EXT)

# RDBMS library components
GLIB_RDBMS_OBJECTS =  gxrdbdef$(OBJ_EXT) \
	gxrdbhdr$(OBJ_EXT) \
	gxrdbms$(OBJ_EXT) \
	gxrdbsql$(OBJ_EXT)

# Extra database library components
GLIB_DATABASE_EX_OBJECTS = btstack$(OBJ_EXT) \
	btcache$(OBJ_EXT) \
	btnode$(OBJ_EXT) \
	dbasekey$(OBJ_EXT) \
	gpersist$(OBJ_EXT) \
	gxbtree$(OBJ_EXT) \
	pod$(OBJ_EXT) \
	gxint16$(OBJ_EXT) \
	gxuint16$(OBJ_EXT) \
	gxfloat$(OBJ_EXT) \
	dbfcache$(OBJ_EXT) \
	dbugmgr$(OBJ_EXT)

# Core socket library components
GLIB_SOCKET_CORE_OBJECTS = gxsocket$(OBJ_EXT)

# Extra socket library components
GLIB_SOCKET_EX_OBJECTS = gxshttp$(OBJ_EXT) \
	gxshttpc$(OBJ_EXT) \
	gxsmtp$(OBJ_EXT) \
	gxsping$(OBJ_EXT) \
	gxspop3$(OBJ_EXT) \
	gxsftp$(OBJ_EXT) \
	gxshtml$(OBJ_EXT) \
	gxsurl$(OBJ_EXT) \
	gxsutils$(OBJ_EXT) \
	gxs_b64$(OBJ_EXT) \
	gxtelnet$(OBJ_EXT) \
	wserror$(OBJ_EXT)

# Database socket library components
GLIB_SOCKET_DB_OBJECTS = gxdatagm$(OBJ_EXT) \
	gxstream$(OBJ_EXT)

# Core serial comm library components
GLIB_SERIAL_CORE_OBJECTS = gxscomm$(OBJ_EXT)

# Database serial com library components
GLIB_SERIAL_DB_OBJECTS = scomserv$(OBJ_EXT)

# Thread library components
GLIB_THREAD_OBJECTS = gthreadt$(OBJ_EXT) \
	gxmutex$(OBJ_EXT) \
	thelpers$(OBJ_EXT) \
	thrapiw$(OBJ_EXT) \
	gxthread$(OBJ_EXT) \
	gxsema$(OBJ_EXT) \
	gxcond$(OBJ_EXT) \
	thrpool$(OBJ_EXT)

# General purpose library components
GLIB_GP_OBJECTS = asprint$(OBJ_EXT) \
	bstreei$(OBJ_EXT)  \
	cdate$(OBJ_EXT)  \
	devcache$(OBJ_EXT) \
	dfileb$(OBJ_EXT) \
	fstring$(OBJ_EXT) \
	futils$(OBJ_EXT) \
	gxconfig$(OBJ_EXT) \
	gxip32$(OBJ_EXT) \
	gxlistb$(OBJ_EXT) \
	gxmac48$(OBJ_EXT) \
	htmldrv$(OBJ_EXT) \
	logfile$(OBJ_EXT) \
	memblock$(OBJ_EXT) \
	membuf$(OBJ_EXT) \
	ostrbase$(OBJ_EXT) \
	pscript$(OBJ_EXT)  \
	strutil$(OBJ_EXT) \
	systime$(OBJ_EXT) \
	ustring$(OBJ_EXT) 

# Optional debug objects
# NOTE: The leak test functions requires the /D__MSVC_DEBUG__ compiler
# flag and the /MDd or /MTd compiler flag. 
GLIB_DEBUG_OBJECTS = leaktest$(OBJ_EXT)

# Term I/O objects
GLIB_TERM_OBJECTS = terminal$(OBJ_EXT)

# Console/GUI messaging gxcode objects
GLIB_MSG_OBJECTS = ehandler$(OBJ_EXT) \
	gxdstats$(OBJ_EXT)

# TODO: Set the library components to compile here
GLIB_OBJECTS = $(GLIB_DATABASE_CORE_OBJECTS) $(GLIB_DATABASE_EX_OBJECTS) \
	$(GLIB_SOCKET_CORE_OBJECTS) $(GLIB_SOCKET_EX_OBJECTS) \
	$(GLIB_SOCKET_DB_OBJECTS) $(GLIB_SERIAL_CORE_OBJECTS) \
	$(GLIB_SERIAL_DB_OBJECTS) $(GLIB_THREAD_OBJECTS) \
	$(GLIB_GP_OBJECTS) $(GLIB_TERM_OBJECTS) \
	$(GLIB_MSG_OBJECTS) $(GLIB_DEBUG_OBJECTS) \
	$(GLIB_RDBMS_OBJECTS)

# Add all additional object files here
OBJECTS = $(PROJECT)$(OBJ_EXT) \
	$(GLIB_DLL_OBJECTS) $(GLIB_OBJECTS) \
	globals$(OBJ_EXT) \
	cryptdb$(OBJ_EXT) \
	aesdb$(OBJ_EXT) \
	rsadb$(OBJ_EXT) \
	smart_card$(OBJ_EXT) \
	c_config$(OBJ_EXT) \
	c_thread$(OBJ_EXT)
# ===============================================================
