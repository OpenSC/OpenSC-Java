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

package org.opensc.pkcs15.asn1.basic;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * The <code>not</code> choice of a SecurityCondition.
 * 
 * @author wglas
 */
public class NotSecurityCondition extends SecurityCondition {

    private SecurityCondition condition;
    
    /**
     * @param condition The SecurityCondition negated by this condition.
     */
    public NotSecurityCondition(SecurityCondition condition) {
        
        this.condition = condition;
    }
    
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.SecurityCondition#checkIdentifier(org.bouncycastle.asn1.ASN1OctetString)
     */
    @Override
    public boolean checkIdentifier(ASN1OctetString identifier) {
        
        if (this.condition == null) return false;
        return !this.condition.checkIdentifier(identifier);
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        return new DERTaggedObject(0,this.condition);
    }

    /**
     * @return The SecurityCondition negated by this condition.
     */
    public SecurityCondition getCondition() {
        return this.condition;
    }

    /**
     * @param condition the condition to set
     */
    public void setCondition(SecurityCondition condition) {
        this.condition = condition;
    }

}
