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
 * Created: 30.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1.attr;

import org.bouncycastle.asn1.DERInteger;
import org.opensc.pkcs15.asn1.Context;
import org.opensc.pkcs15.asn1.ContextHolder;
import org.opensc.pkcs15.asn1.basic.RSAKeyInfo;
import org.opensc.pkcs15.asn1.proxy.Directory;
import org.opensc.pkcs15.asn1.ref.ObjectValueFactory;
import org.opensc.pkcs15.asn1.ref.Path;


/**
 * Decode the ASN.1 <code>ObjectValue {RSAPrivateKeyObject}</code> choice.
 * 
 * @author wglas
 */
public abstract class RSAPrivateKeyObjectFactory {
    
    private static ObjectValueFactory<RSAPrivateKeyObject> factory
    = new ObjectValueFactory<RSAPrivateKeyObject>(RSAPrivateKeyObject.class,RSAPrivateKeyObjectImpl.class);

    /**
     * This method implements the static getInstance factory pattern by
     * using the thread-local context stored in {@link ContextHolder}. 
     * 
     * @param obj ASN.1 object to be decoded.
     * @return A KeyInfo object suitable for RSA Private keys.
     */
    static public RSAPrivateKeyObject getInstance(Object obj)
    {
        Context context = ContextHolder.getContext();
        
        Directory<Path, RSAPrivateKeyObject> directory =
            context == null ? null : context.getRSAPrivateKeyDirectory();
        
        return getInstance(obj,directory);
    }

    /**
     * @param obj An ASN.1 object to resolve.
     * @param directory The directory used to resolve path references.
     * @return An RSAPrivateKeyObjectImpl instance or a RSAPrivateKeyObject proxy
     *         depending on the type of the ReferencedValue. 
     */
    public static RSAPrivateKeyObject getInstance(Object obj,
            Directory<Path,RSAPrivateKeyObject> directory) {
       
        return factory.getInstance(obj, directory);
    }
}
