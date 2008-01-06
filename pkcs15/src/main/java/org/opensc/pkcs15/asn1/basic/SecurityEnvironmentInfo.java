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

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.opensc.pkcs15.asn1.helper.IntegerHelper;

/**
 * <PRE>
 * SecurityEnvironmentInfo ::= SEQUENCE {
 *         se          INTEGER (0..pkcs15-ub-seInfo),
 *         owner       OBJECT IDENTIFIER,
 *         ... -- For future extensions
 *         }
 * </PRE>
 * 
 * @author wglas
 */
public class SecurityEnvironmentInfo extends ASN1Encodable {

    private int se;
    private String owner;
    
    /**
     * Default constructor.
     */
    public SecurityEnvironmentInfo() {
        super();
    }

    /**
     * @param se
     * @param owner
     */
    public SecurityEnvironmentInfo(int se, String owner) {
        super();
        this.se = se;
        this.owner = owner;
    }
    
    public static SecurityEnvironmentInfo getInstance (Object obj)
    {
        if (obj instanceof SecurityEnvironmentInfo)
            return (SecurityEnvironmentInfo)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing se member in SecurityEnvironmentInfo SEQUENCE.");
            
            int se = IntegerHelper.intValue(DERInteger.getInstance(objs.nextElement()).getValue());
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing owner member in SecurityEnvironmentInfo SEQUENCE.");
            
            String owner = DERObjectIdentifier.getInstance(objs.nextElement()).getId();
            
            return new SecurityEnvironmentInfo(se,owner);
        }
        
        throw new IllegalArgumentException("SecurityEnvironmentInfo must be encoded as an ASN.1 SEQUENCE.");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERInteger(this.se));
        v.add(new DERObjectIdentifier(this.owner));

        return new DERSequence(v);
    }

    /**
     * @return the se
     */
    public int getSe() {
        return this.se;
    }

    /**
     * @param se the se to set
     */
    public void setSe(int se) {
        this.se = se;
    }

    /**
     * @return the owner object ID.
     */
    public String getOwner() {
        return this.owner;
    }

    /**
     * @param owner the owner to set
     */
    public void setOwner(String owner) {
        this.owner = owner;
    }

}
