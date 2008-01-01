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
 * Created: 31.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1.sequence;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * An ASN.1 SEQUENCE OF, which may be read from an InputStream in
 * or to decode referenced <code>PathOrObjects</code> instances. 
 * 
 * @author wglas
 */
public class SequenceOfImpl<EntityType extends DEREncodable>  extends ASN1Encodable
implements SequenceOf<EntityType> {

    private List<EntityType> sequence;

    /**
     * Default constructor.
     */
    SequenceOfImpl() {
    }
    
    /**
     * @param sequence The list of elements.
     */
    public SequenceOfImpl(List<EntityType> sequence) {
        super();
        this.sequence = sequence;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (this.sequence != null) {
            
            for (EntityType entity : this.sequence)
                v.add(entity);
        }

        return new DERSequence(v);
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.SequenceOf#getSequence()
     */
    public List<EntityType> getSequence() {
        return this.sequence;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.SequenceOf#setSequence(java.util.List)
     */
    public void setSequence(List<EntityType> sequence) {
        this.sequence = sequence;
    }
    
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.SequenceOf#addEntity(EntityType)
     */
    public void addEntity(EntityType e) {
        
        if (this.sequence == null)
            this.sequence = new ArrayList<EntityType>();
 
        this.sequence.add(e);
    }
}
