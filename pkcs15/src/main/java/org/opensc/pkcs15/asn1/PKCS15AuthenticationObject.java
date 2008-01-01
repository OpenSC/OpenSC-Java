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

package org.opensc.pkcs15.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.opensc.pkcs15.asn1.attr.CommonAuthenticationObjectAttributes;
import org.opensc.pkcs15.asn1.attr.CommonObjectAttributes;

/**
 * This is the base class of all certificate objects.
 * 
 * <PRE>
 * AuthenticationType ::= CHOICE {
 *         pin                AuthenticationObject { PinAttributes },
 *         ...,
 *         biometricTemplate [0] AuthenticationObject {BiometricAttributes},
 *         authKey            [1] AuthenticationObject {AuthKeyAttributes},
 *         external           [2] AuthenticationObject {ExternalAuthObjectAttributes}
 *         }
 * </PRE>
 * 
 * @author wglas
 */
public abstract class PKCS15AuthenticationObject extends ASN1Encodable implements PKCS15Object {

    private CommonObjectAttributes commonObjectAttributes;
    private CommonAuthenticationObjectAttributes commonAuthenticationObjectAttributes;
    
    protected PKCS15AuthenticationObject() {
    }
    
    public static PKCS15AuthenticationObject getInstance(Object obj) {
        
        if (obj instanceof PKCS15AuthenticationObject)
            return (PKCS15AuthenticationObject)obj;
        
        if (obj instanceof ASN1Sequence) {
           // return PKCS15PinAuthenticationObject.getInstance(obj);
        }
            
        if (obj instanceof ASN1TaggedObject) {
            
            ASN1TaggedObject to = (ASN1TaggedObject)obj;
            
            switch (to.getTagNo()) {
            case 0:
                throw new IllegalArgumentException("BiometricAuthenticationObject is not supported.");
            case 1:
                throw new IllegalArgumentException("AuthKeyAuthenticationObject is not supported.");
            case 2:
                throw new IllegalArgumentException("ExternalAuthenticationObject is not supported.");
                
            default:
                throw new IllegalArgumentException("Invalid member tag ["+to.getTagNo()+"] in AuthenticationObject ASN.1 SEQUENCE.");
            }
        }
        
        throw new IllegalArgumentException("AuthenticationObject must be encoded as An ASN.1 SEQUENCE or TAGGED OBJECT.");
    }
    
    /**
     * @return the commonObjectAttributes
     */
    public CommonObjectAttributes getCommonObjectAttributes() {
        return this.commonObjectAttributes;
    }

    /**
     * @param commonObjectAttributes the commonObjectAttributes to set
     */
    public void setCommonObjectAttributes(
            CommonObjectAttributes commonObjectAttributes) {
        this.commonObjectAttributes = commonObjectAttributes;
    }

    /**
     * @return the commonKeyAttributes
     */
    public CommonAuthenticationObjectAttributes getCommonAuthenticationObjectAttributes()
    {
        return this.commonAuthenticationObjectAttributes;
    }

    /**
     * @param commonKeyAttributes the commonKeyAttributes to set
     */
    public void setCommonAuthenticationObjectAttributes(CommonAuthenticationObjectAttributes commonAuthenticationObjectAttributes)
    {
        this.commonAuthenticationObjectAttributes = commonAuthenticationObjectAttributes;
    }
    
}