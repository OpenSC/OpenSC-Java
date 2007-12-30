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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;

/**
 * The ASN.1 representation of the polymorpic KeyIdentifier.
 * 
 * @author wglas
 */
public abstract class KeyIdentifier extends ASN1Encodable {

    public static final int issuerAndSerialNumber = 0; 
    public static final int issuerAndSerialNumberHash = 1;
    public static final int subjectKeyId = 2;
    public static final int subjectKeyHash = 3;
    public static final int issuerKeyHash = 4;
    public static final int issuerNameHash = 5;
    public static final int subjectNameHash = 6;

    private final int id;
    
    /**
     * Protected constructor.
     * 
     * @param id
     */
    protected KeyIdentifier(int id)
    {
        this.id = id;
    }
    
    /**
     * @param o An ASN.1 object to decode.
     * @return A KeyIdentifier instance.
     */
    public static KeyIdentifier getInstance(Object obj)
    {
        if (obj instanceof KeyIdentifier)
            return (KeyIdentifier) obj;
            
        if (obj instanceof ASN1Sequence)
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing id member in KeyIdentifier SEQUENCE.");
            
            DERInteger idin = DERInteger.getInstance(objs.nextElement());
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing value member in KeyIdentifier SEQUENCE.");

            switch (idin.getValue().intValue())
            {
            case issuerAndSerialNumber:
                IssuerAndSerialNumber v = IssuerAndSerialNumber.getInstance(objs.nextElement());
                return new IssuerAndSerialNumberKeyIdentifier(v);
                
            case issuerAndSerialNumberHash:
            case subjectKeyId:
            case subjectKeyHash:
            case issuerKeyHash:
            case issuerNameHash:
            case subjectNameHash:
                ASN1OctetString octets = ASN1OctetString.getInstance(objs.nextElement());
                return new OctetStringKeyIdentifier(idin.getValue().intValue(),octets);
                
            default:
                throw new IllegalArgumentException("Invalid id ["+idin+"] in KeyIdentifier SEQUENCE.");
            }
        }
        
        throw new IllegalArgumentException("KeyIdentifier must be encoded as an ASN.1 SEQUENCE.");
    }
    
    public abstract DEREncodable getValue();
    
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
    
        v.add(new DERInteger(this.id));
        v.add(this.getValue());
        
        return new DERSequence(v);
    }

    /**
     * @return the id
     */
    public int getId() {
        return this.id;
    }

}
