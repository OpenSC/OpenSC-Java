CC=gcc
CFLAGS=-O2 -fPIC -I../../src/jniP11 -I/usr/lib/jvm/java-6-openjdk/include
LD=gcc
LDFLAGS=-shared -s
LIBS=-ljnix -lltdl

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

libopensc-PKCS11-0.2.so: $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

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
	rm -f libopensc-PKCS11-0.2.so $(OBJS)
