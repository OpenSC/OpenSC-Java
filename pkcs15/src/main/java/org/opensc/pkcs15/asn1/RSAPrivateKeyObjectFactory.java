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

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERPrintableString;

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
public abstract class RSAPrivateKeyObjectFactory {
    
    private static ReferenceProxyFactory<Path,RSAPrivateKeyObject>
    proxyFactory = new ReferenceProxyFactory<Path,RSAPrivateKeyObject>(RSAPrivateKeyObject.class);

    /**
     * @param obj
     * @param directory
     * @return
     */
    public static RSAPrivateKeyObject getInstance(Object obj,
            Directory<Path,RSAPrivateKeyObject> directory) {
        
        if (obj instanceof RSAPrivateKeyObject)
            return (RSAPrivateKeyObject) obj;
        
        // ReferencedValue
        
        // Choice 1: indirect / Path 
        if (obj instanceof ASN1Sequence)
            return proxyFactory.getProxy(Path.getInstance(obj),directory);
            
        // Choice 2: indirect / URL
        if (obj instanceof DERPrintableString) {
             throw new IllegalArgumentException("ReferencedValue{RSAPrivateKeyObject}.url CHOICE is not implemented.");
        }
        
        if (obj instanceof ASN1TaggedObject) {
            
            ASN1TaggedObject to = ASN1TaggedObject.getInstance(obj);

            switch(to.getTagNo()) {
            
            case 0:
                // Choice 3: direct
                return RSAPrivateKeyObjectImpl.getInstance(to.getObject());
                
            case 1:
                // Choice 4: indirect-protected
                throw new IllegalArgumentException("ObjectValue{RSAPrivateKeyObject}.indirect-protected CHOICE is not implemented.");
                
            case 2:
                // Choice 5: direct-protected
                throw new IllegalArgumentException("ObjectValue{RSAPrivateKeyObject}.direct-protected CHOICE is not implemented.");         
            
            case 3:
                // Choice 6: indirect / urlWithDigest
                throw new IllegalArgumentException("ReferencedValue{RSAPrivateKeyObject}.urlWithDigest CHOICE is not implemented.");
                
            default:
                throw new IllegalArgumentException("Invalid ObjectValue{RSAPrivateKeyObject} member tag ["+to.getTagNo()+"].");
            }
       }
       
        throw new IllegalArgumentException("ObjectValue {RSAPrivateKeyObject} must be encoded as an ASN.1 SEQUENCE or ASN.1 tagged object.");
    }
}
