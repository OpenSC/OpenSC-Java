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
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyUsage;

/**
 * <PRE>
 * Usage ::= SEQUENCE {
 *         keyUsage     KeyUsage OPTIONAL,
 *         extKeyUsage SEQUENCE SIZE (1..MAX) OF OBJECT IDENTIFIER OPTIONAL
 *         }(WITH COMPONENTS {..., keyUsage PRESENT} |
 *           WITH COMPONENTS {..., extKeyUsage PRESENT})
 * </PRE>
 * 
 * @author wglas
 */
public class Usage extends ASN1Encodable {

    private KeyUsage usage;
    private ExtendedKeyUsage extKeyUsage;
    
    /**
     * Default constructor.
     */
    public Usage() {
        super();
    }

    /**
     * @param obj The ASN.1 object to decode.
     * @return An instance of CommonObjectAttributes.
     */
    public static Usage getInstance (Object obj)
    {
        if (obj instanceof Usage)
            return (Usage)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            Usage ret = new Usage();
            
            while (objs.hasMoreElements()) {
                
                Object o = objs.nextElement();
                
                if (o instanceof ASN1Sequence) {
                    ret.setExtKeyUsage(ExtendedKeyUsage.getInstance(o));
                } else if (o instanceof DERBitString) {
                    ret.setUsage((KeyUsage)KeyUsage.getInstance(o));
                } else
                    throw new IllegalArgumentException("Invalid member ["+o+"] in Usage ASN.1 SEQUENCE.");
            }
               
            return ret;
        }
        
        throw new IllegalArgumentException("CommonKeyAttributes must be encoded as an ASN.1 SEQUENCE.");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (this.usage != null)
            v.add(this.usage);
        
        if (this.extKeyUsage != null)
            v.add(this.extKeyUsage);
        
        return new DERSequence(v);
    }

    /**
     * @return the usage
     */
    public KeyUsage getUsage() {
        return this.usage;
    }

    /**
     * @param usage the usage to set
     */
    public void setUsage(KeyUsage usage) {
        this.usage = usage;
    }

    /**
     * @return the extKeyUsage
     */
    public ExtendedKeyUsage getExtKeyUsage() {
        return this.extKeyUsage;
    }

    /**
     * @param extKeyUsage the extKeyUsage to set
     */
    public void setExtKeyUsage(ExtendedKeyUsage extKeyUsage) {
        this.extKeyUsage = extKeyUsage;
    }

}
