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

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * The <code>and</code> choice of a SecurityCondition.
 * 
 * @author wglas
 */
public class AndSecurityCondition extends SecurityCondition {

    private List<SecurityCondition> conditions;
    
    /**
     * @param condition The SecurityConditions anded by this condition.
     */
    public AndSecurityCondition(List<SecurityCondition> conditions) {
        
        this.conditions = conditions;
    }
    
    /**
     * @param obj The ASN.1 object to be decoded.
     * @return An AndSecurityCondition instance.
     */
    public static AndSecurityCondition getInstance(Object obj) {
        
        if (obj instanceof AndSecurityCondition)
            return (AndSecurityCondition)obj;
        
        if (obj instanceof ASN1Sequence) {
  
            ASN1Sequence seq =(ASN1Sequence)obj;
            
            List<SecurityCondition> conditions = new ArrayList<SecurityCondition>(seq.size());
            
            Enumeration<Object> objs = seq.getObjects();
            
            while (objs.hasMoreElements())
                conditions.add(SecurityCondition.getInstance(objs.nextElement()));
            
            return new AndSecurityCondition(conditions);
        }
        
        throw new IllegalArgumentException("SecurityCondition.and must be encoded as an ASN.1 SEQUENCE.");

    }
    
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.SecurityCondition#checkIdentifier(org.bouncycastle.asn1.ASN1OctetString)
     */
    @Override
    public boolean checkIdentifier(ASN1OctetString identifier) {
        
        if (this.conditions == null) return false;
        
        for (SecurityCondition condition : this.conditions)
        {
            if (!condition.checkIdentifier(identifier))
                return false;
        }
        return true;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (this.conditions != null) 
        {
            for (SecurityCondition condition : this.conditions)
            {
                v.add(condition);
            }
        }

        return new DERSequence(v);
    }

}
