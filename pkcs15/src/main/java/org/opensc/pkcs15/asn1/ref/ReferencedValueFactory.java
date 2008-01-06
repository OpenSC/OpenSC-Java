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

package org.opensc.pkcs15.asn1.ref;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.opensc.pkcs15.asn1.proxy.Directory;
import org.opensc.pkcs15.asn1.proxy.ReferenceProxyFactory;

/**
 * Decode the ASN.1 <code>ReferencedValue {EntityType}</code> choice.
 * 
 * <PRE>
 * ReferencedValue {Type} ::= CHOICE {
 *        path     Path,
 *        url URL
 *        } (CONSTRAINED BY {-- ’path’ or ’url’ shall point to an object of type -- Type})
 * </PRE>
 * 
 * <PRE>
 * URL ::= CHOICE {
 *         url       PrintableString,
 *         urlWithDigest [3] SEQUENCE {
 *             url         IA5String,
 *             digest      DigestInfoWithDefault
 *             }
 *         }
 * </PRE>
 * 
 * @author wglas
 */
public class ReferencedValueFactory<EntityType extends DEREncodable> {
    
    protected final ReferenceProxyFactory<Path,EntityType> pathProxyFactory;

    protected final ReferenceProxyFactory<URL,EntityType> urlProxyFactory;

    protected final URLDirectory<EntityType> urlDirectory;
    protected final String entityName;

    /**
     * Construct a factory for ASN.1 ObjectValues.
     * 
     * @param clazz The class of the EntityType interface, which is implemented by direct
     *              objects and proxies to indirect references.  
     * @param implClazz The class of the implementation of interface, which is instantiated
     *              by direct objects.  
     */
    public ReferencedValueFactory(Class<EntityType> clazz, Class<?> implClazz)
    {
        this.pathProxyFactory = new ReferenceProxyFactory<Path,EntityType>(clazz);
        this.urlProxyFactory = new ReferenceProxyFactory<URL,EntityType>(clazz);
        this.urlDirectory = new URLDirectory<EntityType>(implClazz);
        this.entityName = this.pathProxyFactory.getEntityInterface().getSimpleName();
    }
    
    /**
     * @param obj An ASN.1 object to resolve.
     * @param directory The directory used to resolve path references.
     * @return An instance or a proxy depending on the type of the ReferencedValue. 
     */
    public EntityType getInstance(Object obj,
            Directory<Path,EntityType> directory) {
        
        if (this.pathProxyFactory.getEntityInterface().isAssignableFrom(obj.getClass()))
            return (EntityType) obj;
        
        // ReferencedValue
        
        // Choice 1: indirect / Path 
        if (obj instanceof ASN1Sequence)
            return this.pathProxyFactory.getProxy(Path.getInstance(obj),directory);
            
        // Choice 2: indirect / URL
        if (URL.canGetInstance(obj)) {
            
            return this.urlProxyFactory.getProxy(URL.getInstance(obj),this.urlDirectory);
        }
       
        throw new IllegalArgumentException("ReferencedValue{"+this.entityName+"} must be encoded as an ASN.1 SEQUENCE or ASN.1 tagged object.");
    }
}
