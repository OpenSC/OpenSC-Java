/* jniP11, a JCE cryptographic povider in top of PKCS#11 API
 *
 * Copyright (C) 2006 by ev-i Informationstechnologie GmbH www.ev-i.at
 *
 * Many code-snippets imported from libp11, which is
 *
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <org_opensc_pkcs11_wrap_PKCS11Session.h>

#include <jniP11private.h>

/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    openNative
 * Signature: (JJI)J
 */
JNIEXPORT jlong JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_openNative)
  (JNIEnv *env, jclass jsession, jlong mh, jlong shandle, jint rw)
{
  int rv;
  CK_SESSION_HANDLE hsession;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return 0;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return 0;


  rv = mod->method->C_OpenSession(slot->id,
                                  rw ? (CKF_SERIAL_SESSION | CKF_RW_SESSION) : (CKF_SERIAL_SESSION),
                                  NULL, NULL,
                                  &hsession);
  if (rv != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                         "C_OpenSession for PKCS11 slot %d failed.",
                         (int)slot->id);
      return 0;
    }

   return hsession;
}

/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    closeNative
 * Signature: (JJJ)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_closeNative)
  (JNIEnv *env, jclass jsession, jlong mh, jlong shandle, jlong hsession)
{
  int rv;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  rv = mod->method->C_CloseSession(hsession);
  if (rv != CKR_OK)
    {
      fprintf(stderr,"pkcs11_slot_close_session: C_CloseSession for PKCS11 slot %d(%s) failed.",
              (int)slot->id,mod->name);
    }
}

/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    loginNative
 * Signature: (JJJI[B)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_loginNative)
  (JNIEnv *env, jobject jsession, jlong mh, jlong shandle, jlong hsession, jint type, jbyteArray jpin)
{
  int rv;
  CK_UTF8CHAR_PTR pin=0;
  CK_ULONG pin_len=0;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  if (jpin)
    {
      allocaCArrayFromJByteArray(pin,pin_len,env,jpin);
    }

  rv = mod->method->C_Login(hsession,type,pin,pin_len);
  if (rv != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                         "C_Login for PKCS11 slot %d failed.",
                         (int)slot->id);
      return;
    }
}

/*
 * Class:     org_opensc_pkcs11_wrap_PKCS11Session
 * Method:    logoutNative
 * Signature: (JJJ)V
 */
JNIEXPORT void JNICALL JNIX_FUNC_NAME(Java_org_opensc_pkcs11_wrap_PKCS11Session_logoutNative)
  (JNIEnv *env, jobject jsession, jlong mh, jlong shandle, jlong hsession)
{
  int rv;
  pkcs11_slot_t *slot;
  pkcs11_module_t *mod =  pkcs11_module_from_jhandle(env,mh);
  if (!mod) return;

  slot = pkcs11_slot_from_jhandle(env,shandle);
  if (!slot) return;

  rv = mod->method->C_Logout(hsession);
  if (rv != CKR_OK)
    {
      fprintf(stderr,"PKCS11Session.logoutNative: C_Logout for PKCS11 slot %d(%s) failed (%s).",
              (int)slot->id,mod->name,pkcs11_strerror(rv));
    }
}
