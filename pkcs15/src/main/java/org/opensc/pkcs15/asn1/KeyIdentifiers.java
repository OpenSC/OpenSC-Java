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

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * The ASN.1 representation of a sequence of KeyIdentifiers.
 * 
 * @author wglas
 */
public class KeyIdentifiers extends ASN1Encodable {

    private List<KeyIdentifier> identifiers;
    
    /**
     * Default constructor.
     */
    protected KeyIdentifiers() {
    }
    
    /**
     * Default constructor.
     */
    protected KeyIdentifiers(List<KeyIdentifier> identifiers) {
        this.identifiers = identifiers;
    }
    
    /**
     * @param o An ASN.1 object to decode.
     * @return A KeyIdentifier instance.
     */
    public static KeyIdentifiers getInstance(Object obj)
    {
        if (obj instanceof KeyIdentifiers)
            return (KeyIdentifiers) obj;
            
        if (obj instanceof ASN1Sequence)
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            List<KeyIdentifier> identifiers = new ArrayList<KeyIdentifier>(seq.size());
            
            while (objs.hasMoreElements()) {
             
                identifiers.add(KeyIdentifier.getInstance(objs.nextElement()));
            }
            
            return new KeyIdentifiers(identifiers);
        }
        
        throw new IllegalArgumentException("KeyIdentifiers must be encoded as an ASN.1 SEQUENCE.");
    }
    
   /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
    
        if (this.identifiers != null) {
            
            for (KeyIdentifier identifier : this.identifiers) {
                
                v.add(identifier);
            }
        }
        
        return new DERSequence(v);
    }

}
