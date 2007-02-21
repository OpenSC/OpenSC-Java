# Microsoft Developer Studio Generated NMAKE File, Based on openscPKCS11.dsp
!IF "$(CFG)" == ""
CFG=openscPKCS11 - Win32 Debug
!MESSAGE Keine Konfiguration angegeben. openscPKCS11 - Win32 Debug wird als Standard verwendet.
!ENDIF 

!IF "$(CFG)" != "openscPKCS11 - Win32 Release" && "$(CFG)" != "openscPKCS11 - Win32 Debug"
!MESSAGE Ung�ltige Konfiguration "$(CFG)" angegeben.
!MESSAGE Sie k�nnen beim Ausf�hren von NMAKE eine Konfiguration angeben
!MESSAGE durch Definieren des Makros CFG in der Befehlszeile. Zum Beispiel:
!MESSAGE 
!MESSAGE NMAKE /f "openscPKCS11.mak" CFG="openscPKCS11 - Win32 Debug"
!MESSAGE 
!MESSAGE F�r die Konfiguration stehen zur Auswahl:
!MESSAGE 
!MESSAGE "openscPKCS11 - Win32 Release" (basierend auf  "Win32 (x86) Dynamic-Link Library")
!MESSAGE "openscPKCS11 - Win32 Debug" (basierend auf  "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR Eine ung�ltige Konfiguration wurde angegeben.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "openscPKCS11 - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

ALL : "$(OUTDIR)\opensc-PKCS11-0.3.dll"


CLEAN :
	-@erase "$(INTDIR)\jnix.obj"
	-@erase "$(INTDIR)\org_opensc_pkcs11_PKCS11Provider.obj"
	-@erase "$(INTDIR)\org_opensc_pkcs11_spi_PKCS11CipherSpi.obj"
	-@erase "$(INTDIR)\org_opensc_pkcs11_spi_PKCS11SignatureSpi.obj"
	-@erase "$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11KeyPairGenerator.obj"
	-@erase "$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11Object.obj"
	-@erase "$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11Session.obj"
	-@erase "$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11Slot.obj"
	-@erase "$(INTDIR)\pkcs11_error.obj"
	-@erase "$(INTDIR)\pkcs11_module.obj"
	-@erase "$(INTDIR)\pkcs11_slot.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\opensc-PKCS11-0.3.dll"
	-@erase "$(OUTDIR)\opensc-PKCS11-0.3.exp"
	-@erase "$(OUTDIR)\opensc-PKCS11-0.3.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

F90=df.exe
F90_PROJ=/module:"Release/" /object:"Release/" 
F90_OBJS=.\Release/

.SUFFIXES: .fpp

.for{$(F90_OBJS)}.obj:
   $(F90) $(F90_PROJ) $<  

.f{$(F90_OBJS)}.obj:
   $(F90) $(F90_PROJ) $<  

.f90{$(F90_OBJS)}.obj:
   $(F90) $(F90_PROJ) $<  

.fpp{$(F90_OBJS)}.obj:
   $(F90) $(F90_PROJ) $<  

CPP=cl.exe
CPP_PROJ=/nologo /MT /W3 /GX /O2 /I "$(JAVA_HOME)\include" /I "$(JAVA_HOME)\include\win32" /I "..\..\src\jnix" /I "..\..\src\jniP11" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OPENSCPKCS11_EXPORTS" /D "MSVC6" /Fp"$(INTDIR)\openscPKCS11.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\openscPKCS11.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /incremental:no /pdb:"$(OUTDIR)\opensc-PKCS11-0.3.pdb" /machine:I386 /out:"$(OUTDIR)\opensc-PKCS11-0.3.dll" /implib:"$(OUTDIR)\opensc-PKCS11-0.3.lib" 
LINK32_OBJS= \
	"$(INTDIR)\jnix.obj" \
	"$(INTDIR)\org_opensc_pkcs11_PKCS11Provider.obj" \
	"$(INTDIR)\org_opensc_pkcs11_spi_PKCS11CipherSpi.obj" \
	"$(INTDIR)\org_opensc_pkcs11_spi_PKCS11SignatureSpi.obj" \
	"$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11KeyPairGenerator.obj" \
	"$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11Object.obj" \
	"$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11Session.obj" \
	"$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11Slot.obj" \
	"$(INTDIR)\pkcs11_error.obj" \
	"$(INTDIR)\pkcs11_module.obj" \
	"$(INTDIR)\pkcs11_slot.obj"

"$(OUTDIR)\opensc-PKCS11-0.3.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "openscPKCS11 - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

ALL : "$(OUTDIR)\opensc-PKCS11-0.3.dll"


CLEAN :
	-@erase "$(INTDIR)\jnix.obj"
	-@erase "$(INTDIR)\org_opensc_pkcs11_PKCS11Provider.obj"
	-@erase "$(INTDIR)\org_opensc_pkcs11_spi_PKCS11CipherSpi.obj"
	-@erase "$(INTDIR)\org_opensc_pkcs11_spi_PKCS11SignatureSpi.obj"
	-@erase "$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11KeyPairGenerator.obj"
	-@erase "$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11Object.obj"
	-@erase "$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11Session.obj"
	-@erase "$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11Slot.obj"
	-@erase "$(INTDIR)\pkcs11_error.obj"
	-@erase "$(INTDIR)\pkcs11_module.obj"
	-@erase "$(INTDIR)\pkcs11_slot.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(OUTDIR)\opensc-PKCS11-0.3.dll"
	-@erase "$(OUTDIR)\opensc-PKCS11-0.3.exp"
	-@erase "$(OUTDIR)\opensc-PKCS11-0.3.lib"
	-@erase "$(OUTDIR)\opensc-PKCS11-0.3.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

F90=df.exe
F90_PROJ=/module:"Debug/" /object:"Debug/" 
F90_OBJS=.\Debug/

.SUFFIXES: .fpp

.for{$(F90_OBJS)}.obj:
   $(F90) $(F90_PROJ) $<  

.f{$(F90_OBJS)}.obj:
   $(F90) $(F90_PROJ) $<  

.f90{$(F90_OBJS)}.obj:
   $(F90) $(F90_PROJ) $<  

.fpp{$(F90_OBJS)}.obj:
   $(F90) $(F90_PROJ) $<  

CPP=cl.exe
CPP_PROJ=/nologo /MTd /W3 /Gm /GX /ZI /Od /I "$(JAVA_HOME)\include" /I "$(JAVA_HOME)\include\win32" /I "..\..\src\jnix" /I "..\..\src\jniP11" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "OPENSCPKCS11_EXPORTS" /D "MSVC6" /Fp"$(INTDIR)\openscPKCS11.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\openscPKCS11.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /incremental:no /pdb:"$(OUTDIR)\opensc-PKCS11-0.3.pdb" /debug /machine:I386 /out:"$(OUTDIR)\opensc-PKCS11-0.3.dll" /implib:"$(OUTDIR)\opensc-PKCS11-0.3.lib" /pdbtype:sept 
LINK32_OBJS= \
	"$(INTDIR)\jnix.obj" \
	"$(INTDIR)\org_opensc_pkcs11_PKCS11Provider.obj" \
	"$(INTDIR)\org_opensc_pkcs11_spi_PKCS11CipherSpi.obj" \
	"$(INTDIR)\org_opensc_pkcs11_spi_PKCS11SignatureSpi.obj" \
	"$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11KeyPairGenerator.obj" \
	"$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11Object.obj" \
	"$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11Session.obj" \
	"$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11Slot.obj" \
	"$(INTDIR)\pkcs11_error.obj" \
	"$(INTDIR)\pkcs11_module.obj" \
	"$(INTDIR)\pkcs11_slot.obj"

"$(OUTDIR)\opensc-PKCS11-0.3.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("openscPKCS11.dep")
!INCLUDE "openscPKCS11.dep"
!ELSE 
!MESSAGE Warning: cannot find "openscPKCS11.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "openscPKCS11 - Win32 Release" || "$(CFG)" == "openscPKCS11 - Win32 Debug"
SOURCE=..\..\src\jnix\jnix.c

"$(INTDIR)\jnix.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\src\jniP11\org_opensc_pkcs11_PKCS11Provider.c

"$(INTDIR)\org_opensc_pkcs11_PKCS11Provider.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\src\jniP11\org_opensc_pkcs11_spi_PKCS11CipherSpi.c

"$(INTDIR)\org_opensc_pkcs11_spi_PKCS11CipherSpi.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\src\jniP11\org_opensc_pkcs11_spi_PKCS11SignatureSpi.c

"$(INTDIR)\org_opensc_pkcs11_spi_PKCS11SignatureSpi.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\src\jniP11\org_opensc_pkcs11_wrap_PKCS11KeyPairGenerator.c

"$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11KeyPairGenerator.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\src\jniP11\org_opensc_pkcs11_wrap_PKCS11Object.c

"$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11Object.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\src\jniP11\org_opensc_pkcs11_wrap_PKCS11Session.c

"$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11Session.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\src\jniP11\org_opensc_pkcs11_wrap_PKCS11Slot.c

"$(INTDIR)\org_opensc_pkcs11_wrap_PKCS11Slot.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\src\jniP11\pkcs11_error.c

"$(INTDIR)\pkcs11_error.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\src\jniP11\pkcs11_module.c

"$(INTDIR)\pkcs11_module.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\src\jniP11\pkcs11_slot.c

"$(INTDIR)\pkcs11_slot.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)



!ENDIF 

