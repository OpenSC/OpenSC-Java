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

package org.opensc.pkcs15.asn1.attr;

import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * <PRE>
 * CommonSecretKeyAttributes ::= SEQUENCE {
 *         keyLen INTEGER OPTIONAL, -- keyLength (in bits)
 *      ... -- For future extensions
 *      }
 * </PRE>
 * 
 * @author wglas
 */
public class CommonSecretKeyAttributes extends ASN1Encodable {

    private BigInteger keyLength;
    
    /**
     * Default constructor.
     */
    public CommonSecretKeyAttributes() {
        super();
    }

    /**
     * @param obj The ASN.1 object to decode.
     * @return An instance of CommonSecretKeyAttributes.
     */
    public static CommonSecretKeyAttributes getInstance (Object obj)
    {
        if (obj instanceof CommonSecretKeyAttributes)
            return (CommonSecretKeyAttributes)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            CommonSecretKeyAttributes ret = new CommonSecretKeyAttributes();
            
            while (objs.hasMoreElements()) {
                
                Object o = objs.nextElement();
                
                if (o instanceof DERInteger) {
                    ret.setKeyLength(DERInteger.getInstance(o).getValue());
                } else
                    throw new IllegalArgumentException("Invalid member ["+o+"] in CommonSecretKeyAttributes ASN.1 SEQUENCE.");
            }
               
            return ret;
        }
        
        throw new IllegalArgumentException("CommonSecretKeyAttributes must be encoded as an ASN.1 SEQUENCE.");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (this.keyLength != null)
            v.add(new DERInteger(this.keyLength));

        return new DERSequence(v);
    }

    /**
     * @return the keyLength
     */
    public BigInteger getKeyLength() {
        return this.keyLength;
    }

    /**
     * @param keyLength the keyLength to set
     */
    public void setKeyLength(BigInteger keylength) {
        this.keyLength = keylength;
    }

}
