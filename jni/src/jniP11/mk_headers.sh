#!/bin/sh
#
# $Id$
#
# Author: Wolfgang Glas/ev-i
#
# This script updates the C header files and should be
# executed each time you update the JNI function interfaces
# in the JAVA classes org.opensc.pkcs11.*
#

classes="org.opensc.pkcs11.PKCS11Provider \
         org.opensc.pkcs11.wrap.PKCS11Slot \
         org.opensc.pkcs11.wrap.PKCS11Session \
         org.opensc.pkcs11.wrap.PKCS11Object \
         org.opensc.pkcs11.wrap.PKCS11KeyPairGenerator \
         org.opensc.pkcs11.spi.PKCS11SignatureSpi \
         org.opensc.pkcs11.spi.PKCS11CipherSpi"

for class in $classes
do

  file=`echo $class | sed 's/\./_/g'`

  $JAVA_HOME/bin/javah -classpath ../../../java/bin -d . $class
  rm -f ${file}_*.h

  mv $file.h $file.h~
  sed  -e 's/JNICALL Java_\([a-zA-Z0-9_]*\)/JNICALL JNIX_FUNC_NAME(Java_\1)/' -e 's/#include <jni.h>/#include <jnix.h>/' < $file.h~ > $file.h
done
