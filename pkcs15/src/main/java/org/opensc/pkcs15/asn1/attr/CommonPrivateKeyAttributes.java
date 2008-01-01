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
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.X509Name;
import org.opensc.pkcs15.asn1.basic.KeyIdentifiers;

/**
 * <PRE>
 * CommonPrivateKeyAttributes ::= SEQUENCE {
 *      subjectName Name OPTIONAL,
 *      keyIdentifiers [0] SEQUENCE OF CredentialIdentifier {{KeyIdentifiers}} OPTIONAL,
 *      ... -- For future extensions
 *      }
 * </PRE>
 * 
 * @author wglas
 */
public class CommonPrivateKeyAttributes extends ASN1Encodable {

    private X509Name subjectName;
    private KeyIdentifiers keyIdentifiers;
    
    /**
     * Default constructor.
     */
    public CommonPrivateKeyAttributes() {
        super();
    }

    /**
     * @param obj The ASN.1 object to decode.
     * @return An instance of CommonPrivateKeyAttributes.
     */
    public static CommonPrivateKeyAttributes getInstance (Object obj)
    {
        if (obj instanceof CommonPrivateKeyAttributes)
            return (CommonPrivateKeyAttributes)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            CommonPrivateKeyAttributes ret = new CommonPrivateKeyAttributes();
            
            while (objs.hasMoreElements()) {
                
                Object o = objs.nextElement();
                
                if (o instanceof ASN1Sequence) {
                    ret.setSubjectName(X509Name.getInstance(o));
                } else if (o instanceof ASN1TaggedObject) {
                    
                    ASN1TaggedObject to = (ASN1TaggedObject)o;
                    
                    if (to.getTagNo() != 0)
                        throw new IllegalArgumentException("Invalid member tag ["+to.getTagNo()+"] in member of CommonPrivateKeyAttributes ASN.1 SEQUENCE.");
                    
                    ret.setKeyIdentifiers(KeyIdentifiers.getInstance(to.getObject()));
                        
                } else
                    throw new IllegalArgumentException("Invalid member ["+o+"] in CommonPrivateKeyAttributes ASN.1 SEQUENCE.");
            }
               
            return ret;
        }
        
        throw new IllegalArgumentException("CommonPrivateKeyAttributes must be encoded as an ASN.1 SEQUENCE.");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (this.subjectName != null)
            v.add(this.subjectName);
        
        if (this.keyIdentifiers != null)
            v.add(new DERTaggedObject(0,this.keyIdentifiers));

        return new DERSequence(v);
    }

    /**
     * @return the subjectName
     */
    public X509Name getSubjectName() {
        return this.subjectName;
    }

    /**
     * @param subjectName the subjectName to set
     */
    public void setSubjectName(X509Name subjectName) {
        this.subjectName = subjectName;
    }

    /**
     * @return the keyIdentifiers
     */
    public KeyIdentifiers getKeyIdentifiers() {
        return this.keyIdentifiers;
    }

    /**
     * @param keyIdentifiers the keyIdentifiers to set
     */
    public void setKeyIdentifiers(KeyIdentifiers keyIdentifiers) {
        this.keyIdentifiers = keyIdentifiers;
    }

}
