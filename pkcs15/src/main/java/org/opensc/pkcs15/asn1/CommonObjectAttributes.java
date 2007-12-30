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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * <PRE>
 * CommonObjectAttributes ::= SEQUENCE {
 *      label            Label OPTIONAL,
 *      flags            CommonObjectFlags OPTIONAL,
 *      authId           Identifier OPTIONAL,
 *      ...,
 *      userConsent INTEGER (1..pkcs15-ub-userConsent) OPTIONAL,
 *      accessControlRules SEQUENCE SIZE (1..MAX) OF AccessControlRule OPTIONAL
 *      } (CONSTRAINED BY {-- authId should be present in the IC card case if flags.private is set.
 *      -- It must equal an authID in one AuthRecord in the AODF -- })
 * </PRE>
 * 
 * @author wglas
 */
public class CommonObjectAttributes extends ASN1Encodable {

    private String label;
    private CommonObjectFlags flags;
    private ASN1OctetString authId;
    private BigInteger userConsent;
    private List<AccessControlRule> accessControlRules;
    
    /**
     * Default constructor.
     */
    public CommonObjectAttributes() {
        super();
    }

    private static List<AccessControlRule> getAccessControlRulesInstance(Object obj)
    {
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            Enumeration<Object> objs = seq.getObjects();

            List<AccessControlRule> ret = new ArrayList<AccessControlRule>(seq.size());
            
            while (objs.hasMoreElements())
                ret.add(AccessControlRule.getInstance(objs.nextElement()));
            
            return ret;
        }
        
        throw new IllegalArgumentException("CommonObjectAttributes.accessControlRules must be encoded as an ASN.1 SEQUENCE.");
    }

    /**
     * @param obj The ASN.1 object to decode.
     * @return An instance of CommonObjectAttributes.
     */
    public static CommonObjectAttributes getInstance (Object obj)
    {
        if (obj instanceof CommonObjectAttributes)
            return (CommonObjectAttributes)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            CommonObjectAttributes ret = new CommonObjectAttributes();
            
            while (objs.hasMoreElements()) {
                
                Object o = objs.nextElement();
                
                if (o instanceof DERUTF8String) {
                    ret.setLabel(((DERUTF8String)o).getString());
                } else if (o instanceof DERBitString) {
                    ret.setFlags(CommonObjectFlags.getInstance(o));
                } else if (o instanceof ASN1OctetString) {
                    ret.setAuthId((ASN1OctetString)o);
                } else if (o instanceof DERInteger) {
                    ret.setUserConsent(((DERInteger)o).getValue());
                } else if (o instanceof ASN1Sequence) {
                    ret.setAccessControlRules(getAccessControlRulesInstance(o));
                } else
                    throw new IllegalArgumentException("Invalid member ["+o+"] in CommonObjectAttributes ASN.1 SEQUENCE.");
            }
               
            return ret;
        }
        
        throw new IllegalArgumentException("CommonObjectAttributes must be encoded as an ASN.1 SEQUENCE.");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (this.label != null)
            v.add(new DERUTF8String(this.label));
        if (this.flags != null)
            v.add(this.flags);
        if (this.authId != null)
            v.add(this.authId);
        if (this.userConsent != null)
            v.add(new DERInteger(this.userConsent));
        if (this.accessControlRules != null) {
            
            ASN1EncodableVector va = new ASN1EncodableVector();
            
            for (AccessControlRule rule : this.accessControlRules)
            {
                va.add(rule);
            }
            v.add(new DERSequence(va));
        }
        
        
        return new DERSequence(v);
    }

    /**
     * @return the label
     */
    public String getLabel() {
        return this.label;
    }

    /**
     * @param label the label to set
     */
    public void setLabel(String label) {
        this.label = label;
    }

    /**
     * @return the flags
     */
    public CommonObjectFlags getFlags() {
        return this.flags;
    }

    /**
     * @param flags the flags to set
     */
    public void setFlags(CommonObjectFlags flags) {
        this.flags = flags;
    }

    /**
     * @return the authId
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

    /**
     * @return the userConsent
     */
    public BigInteger getUserConsent() {
        return this.userConsent;
    }

    /**
     * @param userConsent the userConsent to set
     */
    public void setUserConsent(BigInteger userConsent) {
        this.userConsent = userConsent;
    }

    /**
     * @return the accessControlRules
     */
    public List<AccessControlRule> getAccessControlRules() {
        return this.accessControlRules;
    }

    /**
     * @param accessControlRules the accessControlRules to set
     */
    public void setAccessControlRules(List<AccessControlRule> accessControlRules) {
        this.accessControlRules = accessControlRules;
    }

}
