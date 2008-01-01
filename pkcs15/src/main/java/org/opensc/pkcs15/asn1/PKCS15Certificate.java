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
import org.opensc.pkcs15.asn1.attr.CommonCertificateAttributes;
import org.opensc.pkcs15.asn1.attr.CommonObjectAttributes;

/**
 * This is the base class of all certificate objects.
 * 
 * <PRE>
 * CertificateType ::= CHOICE {
 *          x509Certificate             CertificateObject { X509CertificateAttributes},
 *          x509AttributeCertificate    [0] CertificateObject {X509AttributeCertificateAttributes},
 *          spkiCertificate       [1] CertificateObject {SPKICertificateAttributes},
 *          pgpCertificate        [2] CertificateObject {PGPCertificateAttributes},
 *          wtlsCertificate       [3] CertificateObject {WTLSCertificateAttributes},
 *          x9-68Certificate            [4] CertificateObject {X9-68CertificateAttributes},
 *          ...,
 *          cvCertificate               [5] CertificateObject {CVCertificateAttributes}
 *          }
 * </PRE>
 * 
 * @author wglas
 */
public abstract class PKCS15Certificate extends ASN1Encodable implements PKCS15Object {

    private CommonObjectAttributes commonObjectAttributes;
    private CommonCertificateAttributes commonCertificateAttributes;
    
    protected PKCS15Certificate() {
    }
    
    public static PKCS15Certificate getInstance(Object obj) {
        
        if (obj instanceof PKCS15Certificate)
            return (PKCS15Certificate)obj;
        
        if (obj instanceof ASN1Sequence) {
            return PKCS15X509Certificate.getInstance(obj);
        }
            
        if (obj instanceof ASN1TaggedObject) {
            
            ASN1TaggedObject to = (ASN1TaggedObject)obj;
            
            switch (to.getTagNo()) {
            case 0:
                throw new IllegalArgumentException("X509AttributeCertificate is not supported.");
            case 1:
                throw new IllegalArgumentException("SPKICertificate is not supported.");
            case 2:
                throw new IllegalArgumentException("PGPCertificate is not supported.");
            case 3:
                throw new IllegalArgumentException("WTLSCertificate is not supported.");
            case 4:
                throw new IllegalArgumentException("X9-68Certificate is not supported.");
            case 5:
                throw new IllegalArgumentException("CVCertificate is not supported.");
                
            default:
                throw new IllegalArgumentException("Invalid member tag ["+to.getTagNo()+"] in Certificate ASN.1 SEQUENCE.");
            }
            
        }
        
        throw new IllegalArgumentException("Certificate must be encoded as An ASN.1 SEQUENCE or TAGGED OBJECT.");
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
    public CommonCertificateAttributes getCommonCertificateAttributes()
    {
        return this.commonCertificateAttributes;
    }

    /**
     * @param commonKeyAttributes the commonKeyAttributes to set
     */
    public void setCommonCertificateAttributes(CommonCertificateAttributes commonCertificateAttributes)
    {
        this.commonCertificateAttributes = commonCertificateAttributes;
    }
    
}