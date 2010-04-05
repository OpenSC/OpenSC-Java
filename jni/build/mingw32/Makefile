CC=i686-pc-mingw32-gcc
CFLAGS=-O2 -DJNIX_INHIBIT_JNIEXPORT -DWIN32 -D_WINDOWS -D_MBCS -D_WIN32_WINNT=0x501 -I../../src/jniP11
LD=i686-pc-mingw32-gcc
LDFLAGS=-shared -s -Wl,--dll
LIBS=-ljnix

srcdir=../../src/jniP11

SOURCES=org_opensc_pkcs11_PKCS11Provider.c \
     org_opensc_pkcs11_spi_PKCS11CipherSpi.c \
     org_opensc_pkcs11_spi_PKCS11SignatureSpi.c \
     org_opensc_pkcs11_wrap_PKCS11KeyPairGenerator.c \
     org_opensc_pkcs11_wrap_PKCS11Object.c \
     org_opensc_pkcs11_wrap_PKCS11Session.c \
     org_opensc_pkcs11_wrap_PKCS11Slot.c \
     pkcs11_error.c \
     pkcs11_module.c \
     pkcs11_slot.c

OBJS=$(addsuffix .o,$(basename $(SOURCES))) 
DEPENDS=$(addsuffix .d,$(basename $(SOURCES))) 

%.o %.d: $(srcdir)/%.c
	$(CC) $(CFLAGS) -MMD -MT '$*.d $*.o' -c $< -o $*.o

opensc-PKCS11-0.2.dll: $(OBJS) jniP11.def
	$(LD) $(LDFLAGS) $(OBJS) jniP11.def $(LIBS) -o $@

clean:
	rm -f opensc-PKCS11-0.2.dll $(OBJS) $(DEPENDS)

include $(DEPENDS)
