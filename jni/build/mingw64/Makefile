CC=x86_64-pc-mingw32-gcc
CFLAGS=-O2 -DWIN32 -DWIN64 -D_WINDOWS -D_MBCS -D_WIN32_WINNT=0x501 -I../../src/jniP11
LD=x86_64-pc-mingw32-gcc
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

opensc-PKCS11-0.2.dll: $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

clean:
	rm -f opensc-PKCS11-0.2.dll $(OBJS) $(DEPENDS)

include $(DEPENDS)
