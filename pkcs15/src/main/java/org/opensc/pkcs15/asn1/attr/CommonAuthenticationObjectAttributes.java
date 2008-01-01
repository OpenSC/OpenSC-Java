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

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * <PRE>
 * CommonAuthenticationObjectAttributes ::= SEQUENCE {
 *      authId Identifier,
 *      ... -- For future extensions
 *      }
 * </PRE>
 * 
 * @author wglas
 */
public class CommonAuthenticationObjectAttributes extends ASN1Encodable {

    private ASN1OctetString identifier;
    
    /**
     * Default constructor.
     */
    public CommonAuthenticationObjectAttributes() {
        super();
    }

    /**
     * @param obj The ASN.1 object to decode.
     * @return An instance of CommonSecretKeyAttributes.
     */
    public static CommonAuthenticationObjectAttributes getInstance (Object obj)
    {
        if (obj instanceof CommonAuthenticationObjectAttributes)
            return (CommonAuthenticationObjectAttributes)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            CommonAuthenticationObjectAttributes ret = new CommonAuthenticationObjectAttributes();
            
            while (objs.hasMoreElements()) {
                
                Object o = objs.nextElement();
                
                if (o instanceof DERInteger) {
                    ret.setIdentifier(ASN1OctetString.getInstance(o));
                } else
                    throw new IllegalArgumentException("Invalid member ["+o+"] in CommonAuthenticationObjectAttributes ASN.1 SEQUENCE.");
            }
               
            return ret;
        }
        
        throw new IllegalArgumentException("CommonAuthenticationObjectAttributes must be encoded as an ASN.1 SEQUENCE.");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (this.identifier != null)
            v.add(this.identifier);

        return new DERSequence(v);
    }

    /**
     * @return the identifier
     */
    public ASN1OctetString getIdentifier() {
        return this.identifier;
    }

    /**
     * @param identifier the identifier to set
     */
    public void setIdentifier(ASN1OctetString identifier) {
        this.identifier = identifier;
    }

}
