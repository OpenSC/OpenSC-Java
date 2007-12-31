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

package org.opensc.pkcs15.asn1;


/**
 * Decode the ASN.1 <code>ObjectValue {RSAPrivateKeyObject}</code> choice.
 * 
 * @author wglas
 */
public abstract class RSAPrivateKeyObjectFactory {
    
    private static ObjectValueFactory<RSAPrivateKeyObject> factory
    = new ObjectValueFactory<RSAPrivateKeyObject>(RSAPrivateKeyObject.class,RSAPrivateKeyObjectImpl.class);

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
