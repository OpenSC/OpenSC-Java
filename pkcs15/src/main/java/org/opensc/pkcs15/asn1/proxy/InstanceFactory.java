/***********************************************************
 * $Id$
 * 
 * PKCS#15 cryptographic provider of the opensc project.
 * http://www.opensc-project.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Created: 31.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1.proxy;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import org.opensc.pkcs15.asn1.Context;
import org.opensc.pkcs15.asn1.ContextHolder;

/**
 * This class helps to instantiate ASN1 class by their
 * <code>static getInstance(Object)</code> method.  
 * 
 * @author wglas
 */
public class InstanceFactory<T> {

    private final Class<?> clazz;
    private final Method getInstanceMethod;
    
    /**
     * @param clazz The ASN.1 class on which the static <code>getInstace(Object)</code> method is
     *              is invoked. Note, that this might be the class of an actual implementation
     *              or a factory class, if T is an interface.
     */
    public InstanceFactory (Class<?> clazz)
    {
        this.clazz = clazz;
     
        try {
            this.getInstanceMethod = this.clazz.getMethod("getInstance",Object.class);
            
            if (!Modifier.isStatic(this.getInstanceMethod .getModifiers()) ||
                    !Modifier.isPublic(this.getInstanceMethod .getModifiers()) )
                throw new IllegalArgumentException("Method ["+clazz.getName()+".getInstance(Object)] is not static public.");
            
        } catch (NoSuchMethodException e) {
            throw new IllegalArgumentException("Class ["+clazz.getName()+"] has no static getInstance(Object) method.",e);
        }
    }
    
    
    /**
     * @param obj An ASN.1 object.
     * @return A parsed instance of type T.
     */
    public T getInstance(Object obj)
    {
        try {
            return (T)this.getInstanceMethod.invoke(null,obj);
        } catch (InvocationTargetException e) {
            
            if (e.getCause() instanceof RuntimeException)
                throw (RuntimeException)e.getCause();
            
            throw new IllegalArgumentException("Method ["+this.getInstanceMethod+"] has thrown an checked exception.",e);
            
        } catch (IllegalAccessException e) {
            
            throw new IllegalArgumentException("Illegal access to method ["+this.getInstanceMethod+"].",e);
        }
    }

    /**
     * @param obj An ASN.1 object.
     * @return A parsed instance of type T.
     */
    public T getInstance(Object obj, Context context)
    {
        ContextHolder.setContext(context);
        
        try
        {
            return this.getInstance(obj);
        } finally {
            ContextHolder.removeContext();
        }
    }

    /**
     * @return the clazz
     */
    public Class<?> getClazz() {
        return this.clazz;
    }

    /**
     * @return the getInstanceMethod
     */
    public Method getGetInstanceMethod() {
        return this.getInstanceMethod;
    }
}
