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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1TaggedObject;

/**
 * <PRE>
 * SecurityCondition ::= CHOICE {
 *         authId Identifier,
 *         not[0] SecurityCondition,
 *         and         [1] SEQUENCE SIZE (2..pkcs15-ub-securityConditions) OF SecurityCondition,
 *         or          [2] SEQUENCE SIZE (2..pkcs15-ub-securityConditions) OF SecurityCondition,
 *         ... -- For future extensions
 *         }
 * </PRE>
 * 
 * @author wglas
 */
public abstract class SecurityCondition extends ASN1Encodable {

    /**
     * Check, whether this security condition allows access to the given
     * identifier.
     * 
     * @param identifier The identifier to check.
     * @return Whether this identifier is granted access by this security condition.
     */
    public abstract boolean checkIdentifier(ASN1OctetString identifier);
    
    /**
     * Constructor to be used by subclasses. 
     */
    protected SecurityCondition() {
    }
    
    /**
     * @param obj The ASN.1 object to be decoded.
     * @return A SecurityCondition instance.
     */
    public static SecurityCondition getInstance (Object obj)
    {
        if (obj instanceof SecurityCondition)
            return (SecurityCondition) obj;
         
        if (obj instanceof ASN1OctetString)
            return new AuthIdSecurityCondition((ASN1OctetString)obj);
        
        if (obj instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject to = ASN1TaggedObject.getInstance(obj);

            switch(to.getTagNo()) {
            
            case 0:
                return new NotSecurityCondition(SecurityCondition.getInstance(to.getObject()));
                
            case 1:
                return AndSecurityCondition.getInstance(to.getObject());
                
            default:
                throw new IllegalArgumentException("Invalid SecurityCondition member tag ["+to.getTagNo()+"].");
                
            }
        }
            
        throw new IllegalArgumentException("SecurityCondition must be encoded as an ASN.1 OCTET STRING or ASN.1 tagged object.");
    }
    
}
