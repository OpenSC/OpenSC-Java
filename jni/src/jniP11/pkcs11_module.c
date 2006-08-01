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

#include <jniP11private.h>
#include <stdlib.h>

#ifdef DEBUG
# define DEBUG_PKCS11_MODULE
#endif

#ifdef WIN32
#include <windows.h>

static CK_RV pkcs11_create_mutex(CK_VOID_PTR_PTR ppMutex)
{
  if (ppMutex == NULL) return CKR_ARGUMENTS_BAD;

  LPCRITICAL_SECTION cs = (LPCRITICAL_SECTION)malloc(sizeof(CRITICAL_SECTION));

  if (cs == NULL) return CKR_HOST_MEMORY;

  InitializeCriticalSection(cs);
  
  *ppMutex = (CK_VOID_PTR)cs;

  return CKR_OK;
}

static CK_RV pkcs11_destroy_mutex(CK_VOID_PTR pMutex)
{
  if (pMutex == NULL) return CKR_ARGUMENTS_BAD;

  LPCRITICAL_SECTION cs = (LPCRITICAL_SECTION)pMutex;

  DeleteCriticalSection(cs);
  free(cs);
 
  return CKR_OK;
}

static CK_RV pkcs11_lock_mutex(CK_VOID_PTR pMutex)
{
  if (pMutex == NULL) return CKR_ARGUMENTS_BAD;

  LPCRITICAL_SECTION cs = (LPCRITICAL_SECTION)pMutex;

  EnterCriticalSection(cs);
 
  return CKR_OK;
}

static CK_RV pkcs11_unlock_mutex(CK_VOID_PTR pMutex)
{
  if (pMutex == NULL) return CKR_ARGUMENTS_BAD;

  LPCRITICAL_SECTION cs = (LPCRITICAL_SECTION)pMutex;

  LeaveCriticalSection(cs);
 
  return CKR_OK;
}
#else

#include <pthread.h>
#include <ltdl.h>

static CK_RV pkcs11_create_mutex(CK_VOID_PTR_PTR ppMutex)
{
  if (ppMutex == NULL) return CKR_ARGUMENTS_BAD;

  pthread_mutex_t *mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));

  if (mutex == NULL) return CKR_HOST_MEMORY;

  if (pthread_mutex_init(mutex,NULL))
    {
      free(mutex);
      return CKR_GENERAL_ERROR;
    }
  
  *ppMutex = (CK_VOID_PTR)mutex;

  return CKR_OK;
}

static CK_RV pkcs11_destroy_mutex(CK_VOID_PTR pMutex)
{
  if (pMutex == NULL) return CKR_ARGUMENTS_BAD;

  pthread_mutex_t *mutex = (pthread_mutex_t *)pMutex;

  pthread_mutex_destroy(mutex);
  free(mutex);
 
  return CKR_OK;
}

static CK_RV pkcs11_lock_mutex(CK_VOID_PTR pMutex)
{
  if (pMutex == NULL) return CKR_ARGUMENTS_BAD;

  pthread_mutex_t * mutex = (pthread_mutex_t *)pMutex;

  if (pthread_mutex_lock(mutex))
    return CKR_GENERAL_ERROR;
 
  return CKR_OK;
}

static CK_RV pkcs11_unlock_mutex(CK_VOID_PTR pMutex)
{
  if (pMutex == NULL) return CKR_ARGUMENTS_BAD;

  pthread_mutex_t *mutex = (pthread_mutex_t *)pMutex;

  if (pthread_mutex_unlock(mutex))
    return CKR_GENERAL_ERROR;
 
  return CKR_OK;
}

#endif

pkcs11_module_t *new_pkcs11_module(JNIEnv *env, const char *c_filename)
{
  int rv;
  CK_RV (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);

  pkcs11_module_t *mod = (pkcs11_module_t *) malloc(sizeof(pkcs11_module_t));

  if (!mod)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Out of memory allocating PKCS11 context.");
      return 0;
    }

  mod->_magic = PKCS11_MODULE_MAGIC;
  mod->name = strdup(c_filename);

#ifdef WIN32
  mod->handle = LoadLibraryA(c_filename);

  if (mod->handle == INVALID_HANDLE_VALUE)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Cannot open PKCS11 module %s.",c_filename);
      goto failed;
    }
#else
  if (lt_dlinit() != 0)
   {
     jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                        "Unable ot initialize dynamic function loading.");
     return 0;
   }

   mod->handle = lt_dlopen(c_filename);

  if (mod->handle == NULL)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Cannot open PKCS11 module %s: %s.",c_filename,lt_dlerror());
      goto failed;
    }
#endif

#ifdef WIN32
  c_get_function_list = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
    GetProcAddress(mod->handle, "C_GetFunctionList");
#else
  c_get_function_list = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
    lt_dlsym(mod->handle, "C_GetFunctionList");
#endif

  if (!c_get_function_list)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Cannot find function C_GetFunctionList in PKCS11 module %s.",c_filename);
      goto failed;
    }

  rv = c_get_function_list(&mod->method);
  if (rv != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_GetFunctionList in PKCS11 module %s failed.",
                          c_filename);
      goto failed;
    }

  CK_C_INITIALIZE_ARGS init_args =
    {
      pkcs11_create_mutex,
      pkcs11_destroy_mutex,
      pkcs11_lock_mutex,
      pkcs11_unlock_mutex,
      CKF_OS_LOCKING_OK,
      NULL
    };

  rv = mod->method->C_Initialize(&init_args);
  if (rv != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_Initialize in PKCS11 module %s failed.",
                          c_filename);
      goto failed;
    }
  
  /* Get info on the library */
  rv = mod->method->C_GetInfo(&mod->ck_info);
  if (rv != CKR_OK)
    {
      jnixThrowExceptionI(env,"org/opensc/pkcs11/wrap/PKCS11Exception",rv,
                          "C_GetInfo in PKCS11 module %s failed.",c_filename);
      goto failed;
    }

#ifdef DEBUG_PKCS11_MODULE
  fprintf(stderr,"Loaded module: %s.\n",c_filename);
  fprintf(stderr,"handle= %p.\n",mod);
  fprintf(stderr,"version= %d.%d.\n",
          (int)mod->ck_info.cryptokiVersion.major,
          (int)mod->ck_info.cryptokiVersion.minor );
  fprintf(stderr,"manufacturer= %.32s.\n",mod->ck_info.manufacturerID);
  fprintf(stderr,"description= %.32s.\n",mod->ck_info.libraryDescription);
#endif

 return mod;

failed:
  if (mod->name) free(mod->name);
 
#ifdef WIN32
  if (mod->handle!=INVALID_HANDLE_VALUE)
    FreeLibrary(mod->handle);
#else
  if (mod->handle)
    lt_dlclose(mod->handle);
#endif
  free(mod);

#ifndef WIN32
  lt_dlexit();
#endif
  return 0;
}

jlong pkcs11_module_to_jhandle(JNIEnv *env, pkcs11_module_t *mod)
{
  return (jlong)(size_t)mod;
}

pkcs11_module_t *pkcs11_module_from_jhandle(JNIEnv *env, jlong handle)
{
  pkcs11_module_t *mod = (pkcs11_module_t *)(size_t)handle;

  if (!mod || mod->_magic != PKCS11_MODULE_MAGIC)
    {
      jnixThrowException(env,"org/opensc/pkcs11/wrap/PKCS11Exception",
                         "Invalid PKCS 11 module handle %p.",mod);
      return 0;
    }
  
  return mod;
}

void destroy_pkcs11_module(JNIEnv *env, pkcs11_module_t *mod)
{
 
#ifdef DEBUG_PKCS11_MODULE
  fprintf(stderr,"Unloading module: %s.\n",mod->name);
  fprintf(stderr,"handle= %p.\n",mod);
#endif

  /* Tell the PKCS11 library to shut down */
  mod->method->C_Finalize(NULL);

#ifdef WIN32
  if (mod->handle!=INVALID_HANDLE_VALUE)
    FreeLibrary(mod->handle);
#else
  if (mod->handle)
    lt_dlclose(mod->handle);
#endif

  if (mod->name) free(mod->name);

  memset(mod, 0, sizeof(pkcs11_module_t));
  free(mod);

#ifndef WIN32
  lt_dlexit();
#endif
}
