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
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.opensc.pkcs15.asn1.helper.IntegerHelper;

/**
 * <PRE>
 * RecordInfo ::= SEQUENCE {
 *        oDFRecordLength          [0] INTEGER (0..pkcs15-ub-recordLength) OPTIONAL,
 *        prKDFRecordLength        [1] INTEGER (0..pkcs15-ub-recordLength) OPTIONAL,
 *        puKDFRecordLength        [2] INTEGER (0..pkcs15-ub-recordLength) OPTIONAL,
 *        sKDFRecordLength         [3] INTEGER (0..pkcs15-ub-recordLength) OPTIONAL,
 *        cDFRecordLength          [4] INTEGER (0..pkcs15-ub-recordLength) OPTIONAL,
 *        dODFRecordLength         [5] INTEGER (0..pkcs15-ub-recordLength) OPTIONAL,
 *        aODFRecordLength         [6] INTEGER (0..pkcs15-ub-recordLength) OPTIONAL
 *        }
 * </PRE>
 * 
 * @author wglas
 */
public class RecordInfo extends ASN1Encodable {

    private Integer oDFRecordLength;
    private Integer prKDFRecordLength;
    private Integer puKDFRecordLength;
    private Integer sKDFRecordLength;
    private Integer cDFRecordLength;
    private Integer dODFRecordLength;
    private Integer aODFRecordLength;

    
    /**
     * Default constructor.
     */
    public RecordInfo() {
        super();
    }

    public static RecordInfo getInstance (Object obj)
    {
        if (obj instanceof RecordInfo)
            return (RecordInfo)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            RecordInfo ret = new RecordInfo();
            
            while (objs.hasMoreElements()) {
                
                ASN1TaggedObject to = ASN1TaggedObject.getInstance(objs.nextElement());
                
                Integer i = IntegerHelper.toInteger(DERInteger.getInstance(to.getObject()).getValue());

                switch (to.getTagNo()) {
                
                case 0:
                    ret.setODFRecordLength(i);
                    break;
                    
                case 1:
                    ret.setPrKDFRecordLength(i);
                    break;
                    
                case 2:
                    ret.setPuKDFRecordLength(i);
                    break;
                    
                case 3:
                    ret.setSKDFRecordLength(i);
                    break;
                    
                case 4:
                    ret.setCDFRecordLength(i);
                    break;
                    
                case 5:
                    ret.setDODFRecordLength(i);
                    break;
                    
                case 6:
                    ret.setAODFRecordLength(i);
                    break;
                    
                default:
                    throw new IllegalArgumentException("Invalid member tag ["+to.getTagNo()+"] in RecordInfo.");
                }   
            }
            
            return ret;
        }
        
        throw new IllegalArgumentException("SecurityEnvironmentInfo must be encoded as an ASN.1 SEQUENCE.");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (this.oDFRecordLength != null)
            v.add(new DERTaggedObject(0,new DERInteger(this.oDFRecordLength.intValue())));
        
        if (this.prKDFRecordLength != null)
            v.add(new DERTaggedObject(1,new DERInteger(this.prKDFRecordLength.intValue())));
            
        if (this.puKDFRecordLength != null)
            v.add(new DERTaggedObject(2,new DERInteger(this.puKDFRecordLength.intValue())));
        
        if (this.sKDFRecordLength != null)
            v.add(new DERTaggedObject(3,new DERInteger(this.sKDFRecordLength.intValue())));
        
        if (this.cDFRecordLength != null)
            v.add(new DERTaggedObject(4,new DERInteger(this.cDFRecordLength.intValue())));
        
        if (this.dODFRecordLength != null)
            v.add(new DERTaggedObject(5,new DERInteger(this.dODFRecordLength.intValue())));
        
        if (this.aODFRecordLength != null)
            v.add(new DERTaggedObject(6,new DERInteger(this.aODFRecordLength.intValue())));
        
        return new DERSequence(v);
    }

    /**
     * @return the oDFRecordLength
     */
    public Integer getODFRecordLength() {
        return this.oDFRecordLength;
    }

    /**
     * @param recordLength the oDFRecordLength to set
     */
    public void setODFRecordLength(Integer recordLength) {
        this.oDFRecordLength = recordLength;
    }

    /**
     * @return the prKDFRecordLength
     */
    public Integer getPrKDFRecordLength() {
        return this.prKDFRecordLength;
    }

    /**
     * @param prKDFRecordLength the prKDFRecordLength to set
     */
    public void setPrKDFRecordLength(Integer prKDFRecordLength) {
        this.prKDFRecordLength = prKDFRecordLength;
    }

    /**
     * @return the puKDFRecordLength
     */
    public Integer getPuKDFRecordLength() {
        return this.puKDFRecordLength;
    }

    /**
     * @param puKDFRecordLength the puKDFRecordLength to set
     */
    public void setPuKDFRecordLength(Integer puKDFRecordLength) {
        this.puKDFRecordLength = puKDFRecordLength;
    }

    /**
     * @return the sKDFRecordLength
     */
    public Integer getSKDFRecordLength() {
        return this.sKDFRecordLength;
    }

    /**
     * @param recordLength the sKDFRecordLength to set
     */
    public void setSKDFRecordLength(Integer recordLength) {
        this.sKDFRecordLength = recordLength;
    }

    /**
     * @return the cDFRecordLength
     */
    public Integer getCDFRecordLength() {
        this.return cDFRecordLength;
    }

    /**
     * @param recordLength the cDFRecordLength to set
     */
    public void setCDFRecordLength(Integer recordLength) {
        this.cDFRecordLength = recordLength;
    }

    /**
     * @return the dODFRecordLength
     */
    public Integer getDODFRecordLength() {
        return this.dODFRecordLength;
    }

    /**
     * @param recordLength the dODFRecordLength to set
     */
    public void setDODFRecordLength(Integer recordLength) {
        this.dODFRecordLength = recordLength;
    }

    /**
     * @return the aODFRecordLength
     */
    public Integer getAODFRecordLength() {
        return this.aODFRecordLength;
    }

    /**
     * @param recordLength the aODFRecordLength to set
     */
    public void setAODFRecordLength(Integer recordLength) {
        this.aODFRecordLength = recordLength;
    }
    
}
