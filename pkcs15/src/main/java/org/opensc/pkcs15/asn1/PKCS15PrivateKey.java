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
import org.opensc.pkcs15.asn1.attr.CommonKeyAttributes;
import org.opensc.pkcs15.asn1.attr.CommonObjectAttributes;
import org.opensc.pkcs15.asn1.attr.CommonPrivateKeyAttributes;

/**
 * This is the base class of all private key objects.
 * <PRE>
 * PrivateKeyType ::= CHOICE {
 *         privateRSAKey PrivateKeyObject {PrivateRSAKeyAttributes},
 *         privateECKey            [0] PrivateKeyObject {PrivateECKeyAttributes},
 *         privateDHKey            [1] PrivateKeyObject {PrivateDHKeyAttributes},
 *         privateDSAKey [2] PrivateKeyObject {PrivateDSAKeyAttributes},
 *         privateKEAKey [3] PrivateKeyObject {PrivateKEAKeyAttributes},
 *         ... -- For future extensions
 *         }
 * </PRE>
 *
 * @author wglas
 */
public abstract class PKCS15PrivateKey extends ASN1Encodable implements PKCS15Key {

    private CommonObjectAttributes commonObjectAttributes;
    private CommonKeyAttributes commonKeyAttributes;
    private CommonPrivateKeyAttributes commonPrivateKeyAttributes;
    
    protected PKCS15PrivateKey() {
    }
    
    public static PKCS15PrivateKey getInstance(Object obj) {
        
        if (obj instanceof PKCS15PrivateKey)
            return (PKCS15PrivateKey)obj;
        
        if (obj instanceof ASN1Sequence) {
            return PKCS15RSAPrivateKey.getInstance(obj);
        }
            
        if (obj instanceof ASN1TaggedObject) {
            
            ASN1TaggedObject to = (ASN1TaggedObject)obj;
            
            switch (to.getTagNo()) {
            case 0:
                throw new IllegalArgumentException("PrivateECKey is not supported.");
            case 1:
                throw new IllegalArgumentException("PrivateDHKey is not supported.");
            case 2:
                throw new IllegalArgumentException("PrivateDSAKey is not supported.");
            case 3:
                throw new IllegalArgumentException("PrivateKEAKey is not supported.");
                 
            default:
                throw new IllegalArgumentException("Invalid member tag ["+to.getTagNo()+"] in PrivateKey ASN.1 SEQUENCE.");
            }
            
        }
        
        throw new IllegalArgumentException("PrivateKey must be encoded as An ASN.1 SEQUENCE or TAGGED OBJECT.");
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
    public CommonKeyAttributes getCommonKeyAttributes() {
        return this.commonKeyAttributes;
    }
    /**
     * @param commonKeyAttributes the commonKeyAttributes to set
     */
    public void setCommonKeyAttributes(CommonKeyAttributes commonKeyAttributes) {
        this.commonKeyAttributes = commonKeyAttributes;
    }
    /**
     * @return the commonPrivateKeyAttributes
     */
    public CommonPrivateKeyAttributes getCommonPrivateKeyAttributes() {
        return this.commonPrivateKeyAttributes;
    }
    /**
     * @param commonPrivateKeyAttributes the commonPrivateKeyAttributes to set
     */
    public void setCommonPrivateKeyAttributes(
            CommonPrivateKeyAttributes commonPrivateKeyAttributes) {
        this.commonPrivateKeyAttributes = commonPrivateKeyAttributes;
    }
}