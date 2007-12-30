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

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERObject;

/**
 * The <code>authId</code> choice of a SecurityCondition.
 * 
 * @author wglas
 */
public class AuthIdSecurityCondition extends SecurityCondition {

    private ASN1OctetString authId;
    
    /**
     * @param authId The The Id of the object covered by this condition.
     */
    public AuthIdSecurityCondition(ASN1OctetString authId) {
        
        this.authId = authId;
    }
    
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.SecurityCondition#checkIdentifier(org.bouncycastle.asn1.ASN1OctetString)
     */
    @Override
    public boolean checkIdentifier(ASN1OctetString identifier) {
        
        if (this.authId == null) return false;
        return this.authId.equals(identifier);
    }

    /**
     * @return The The Id of the object covered by this condition.
     */
    public ASN1OctetString getAuthId() {
        return this.authId;
    }

    /**
     * @param authId the authId to set
     */
    public void setAuthId(ASN1OctetString authId) {
        this.authId = authId;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        return this.authId;
    }

}
