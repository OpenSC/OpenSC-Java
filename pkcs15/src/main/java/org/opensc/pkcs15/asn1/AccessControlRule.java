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

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * <PRE>
 * AccessControlRule ::= SEQUENCE {
 *        accessMode            AccessMode,
 *        securityCondition     SecurityCondition,
 *        ... -- For future extensions
 *        }
 * </PRE>
 * 
 * @author wglas
 */
public class AccessControlRule extends ASN1Encodable {

    private AccessMode accessMode;
    private SecurityCondition securityCondition;
    
    /**
     * Default constructor.
     */
    public AccessControlRule() {
        super();
    }

    /**
     * @param accessMode
     * @param securityCondition
     */
    public AccessControlRule(AccessMode accessMode,
            SecurityCondition securityCondition) {
        super();
        this.accessMode = accessMode;
        this.securityCondition = securityCondition;
    }
    
    public static AccessControlRule getInstance (Object obj)
    {
        if (obj instanceof AccessControlRule)
            return (AccessControlRule)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing accessMode member in AccessControlRule SEQUENCE.");
            
            AccessMode accessMode = AccessMode.getInstance(objs.nextElement());
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing securityCondition member in AccessControlRule SEQUENCE.");
            
            SecurityCondition securityCondition = SecurityCondition.getInstance(objs.nextElement());
            
            return new AccessControlRule(accessMode,securityCondition);
        }
        
        throw new IllegalArgumentException("AccessControlRule must be encoded as an ASN.1 SEQUENCE.");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(this.accessMode);
        v.add(this.securityCondition);

        return new DERSequence(v);
    }

    /**
     * @return the accessMode
     */
    public AccessMode getAccessMode() {
        return this.accessMode;
    }

    /**
     * @param accessMode the accessMode to set
     */
    public void setAccessMode(AccessMode accessMode) {
        this.accessMode = accessMode;
    }

    /**
     * @return the securityCondition
     */
    public SecurityCondition getSecurityCondition() {
        return this.securityCondition;
    }

    /**
     * @param securityCondition the securityCondition to set
     */
    public void setSecurityCondition(SecurityCondition securityCondition) {
        this.securityCondition = securityCondition;
    }

}
