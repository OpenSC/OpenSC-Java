CC=gcc
CFLAGS=-g -O2 -fPIC -I../../src/jniP11 -I/usr/lib/jvm/java-6-openjdk/include
LD=gcc
LDFLAGS=-shared
LIBS=-ljnix -lltdl

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

libopensc-PKCS11-0.2.so: $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) $(LIBS) -o $@


clean:
	rm -f libopensc-PKCS11-0.2.so $(OBJS) $(DEPENDS)

include $(DEPENDS)