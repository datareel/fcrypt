all:
	nmake -f fcrypt.vc all
	nmake -f fdecrypt.vc all
	nmake -f fmigrate.vc all

install:
	copy fcrypt.exe ..\bin\fcrypt.exe
	copy fdecrypt.exe ..\bin\fdecrypt.exe
	copy fmigrate.exe ..\bin\fmigrate.exe

clean:
	nmake -f fcrypt.vc clean
	nmake -f fdecrypt.vc clean
	nmake -f fmigrate.vc clean
