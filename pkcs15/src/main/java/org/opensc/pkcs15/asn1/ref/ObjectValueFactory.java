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

import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.opensc.pkcs15.asn1.proxy.Directory;

/**
 * Decode the ASN.1 <code>ObjectValue {RSAPrivateKeyObject}</code> choice.
 * 
 * <PRE>
 * ObjectValue { Type } ::= CHOICE {
 *        indirect                  ReferencedValue {Type},
 *        direct                    [0] Type,
 *        indirect-protected        [1] ReferencedValue {EnvelopedData {Type}},
 *        direct-protected          [2] EnvelopedData {Type},
 *        }(CONSTRAINED BY {-- if indirection is being used, then it is expected that the reference
 *        -- points either to a (possibly enveloped) object of type -- Type -- or (key case) to a card-
 *        -- specific key file --})
 * </PRE>
 * 
 * @author wglas
 */
public class ObjectValueFactory<EntityType extends DEREncodable> extends ReferencedValueFactory<EntityType> {
    
    /**
     * Construct a factory for ASN.1 ObjectValues.
     * 
     * @param clazz The class of the EntityType interface, which is implemented by direct
     *              objects and proxies to indirect references.  
     * @param implClazz The class of the implementation of interface, which is instantiated
     *              by direct objects.  
     */
    public ObjectValueFactory(Class<EntityType> clazz, Class<?> implClazz)
    {
        super(clazz,implClazz);
    }
    
    /**
     * @param obj An ASN.1 object to resolve.
     * @param directory The directory used to resolve path references.
     * @return An instance or a proxy depending on the type of the ReferencedValue. 
     */
    public EntityType getInstance(Object obj,
            Directory<Path,EntityType> directory) {
        
        if (obj instanceof ASN1TaggedObject) {
            
            ASN1TaggedObject to = ASN1TaggedObject.getInstance(obj);

            switch(to.getTagNo()) {
            
            case 0:
                // Choice 0: direct
                return this.urlDirectory.getInstanceFactory().getInstance(to.getObject());
                
            case 1:
                // Choice 1: indirect-protected
                throw new IllegalArgumentException("ObjectValue{"+this.entityName+"}.indirect-protected CHOICE is not implemented.");
                
            case 2:
                // Choice 2: direct-protected
                throw new IllegalArgumentException("ObjectValue{"+this.entityName+"}.direct-protected CHOICE is not implemented.");         
            
            case 3:
                // URL ReferencedValue is handler by superclass.
                break;
                
            default:
                throw new IllegalArgumentException("Invalid ObjectValue{"+this.entityName+"} member tag ["+to.getTagNo()+"].");
            }
        }
       
        // all other possibilities are handled by ReferencedValueFactory.
        return super.getInstance(obj, directory);
    }
}
