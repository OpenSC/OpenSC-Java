CC=i686-pc-mingw32-gcc
CFLAGS=-O2 -DJNIX_INHIBIT_JNIEXPORT -DWIN32 -D_WINDOWS -D_MBCS -D_WIN32_WINNT=0x501 -I../../src/jniP11
LD=i686-pc-mingw32-gcc
LDFLAGS=-shared -s -Wl,--dll
LIBS=-ljnix

srcdir=../../src/jniP11

OBJS=org_opensc_pkcs11_PKCS11Provider.o \
     org_opensc_pkcs11_spi_PKCS11CipherSpi.o \
     org_opensc_pkcs11_spi_PKCS11SignatureSpi.o \
     org_opensc_pkcs11_wrap_PKCS11KeyPairGenerator.o \
     org_opensc_pkcs11_wrap_PKCS11Object.o \
     org_opensc_pkcs11_wrap_PKCS11Session.o \
     org_opensc_pkcs11_wrap_PKCS11Slot.o \
     pkcs11_error.o \
     pkcs11_module.o \
     pkcs11_slot.o


%.o: $(srcdir)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

opensc-PKCS11-0.2.dll: $(OBJS) jniP11.def
	$(LD) $(LDFLAGS) $(OBJS) jniP11.def $(LIBS) -o $@

org_opensc_pkcs11_PKCS11Provider.o: \
 $(srcdir)/org_opensc_pkcs11_PKCS11Provider.c \
 $(srcdir)/org_opensc_pkcs11_PKCS11Provider.h \
 $(srcdir)/jniP11private.h

org_opensc_pkcs11_spi_PKCS11CipherSpi.o: \
 $(srcdir)/org_opensc_pkcs11_spi_PKCS11CipherSpi.c \
 $(srcdir)/org_opensc_pkcs11_spi_PKCS11CipherSpi.h \
 $(srcdir)/jniP11private.h

org_opensc_pkcs11_spi_PKCS11SignatureSpi.o: \
 $(srcdir)/org_opensc_pkcs11_spi_PKCS11SignatureSpi.c \
 $(srcdir)/org_opensc_pkcs11_spi_PKCS11SignatureSpi.h \
 $(srcdir)/jniP11private.h

org_opensc_pkcs11_wrap_PKCS11KeyPairGenerator.o: \
 $(srcdir)/org_opensc_pkcs11_wrap_PKCS11KeyPairGenerator.c \
 $(srcdir)/org_opensc_pkcs11_wrap_PKCS11KeyPairGenerator.h \
 $(srcdir)/jniP11private.h

org_opensc_pkcs11_wrap_PKCS11Object.o: \
 $(srcdir)/org_opensc_pkcs11_wrap_PKCS11Object.c \
 $(srcdir)/org_opensc_pkcs11_wrap_PKCS11Object.h \
 $(srcdir)/jniP11private.h

org_opensc_pkcs11_wrap_PKCS11Session.o: \
 $(srcdir)/org_opensc_pkcs11_wrap_PKCS11Session.c \
 $(srcdir)/org_opensc_pkcs11_wrap_PKCS11Session.h \
 $(srcdir)/jniP11private.h

org_opensc_pkcs11_wrap_PKCS11Slot.o: \
 $(srcdir)/org_opensc_pkcs11_wrap_PKCS11Slot.c \
 $(srcdir)/org_opensc_pkcs11_wrap_PKCS11Slot.h \
 $(srcdir)/jniP11private.h

pkcs11_error.o: \
 $(srcdir)/pkcs11_error.c \
 $(srcdir)/jniP11private.h

pkcs11_module.o: \
 $(srcdir)/pkcs11_module.c \
 $(srcdir)/jniP11private.h

pkcs11_slot.o: \
 $(srcdir)/pkcs11_slot.c \
 $(srcdir)/jniP11private.h

clean:
	rm -f opensc-PKCS11-0.2.dll $(OBJS)
