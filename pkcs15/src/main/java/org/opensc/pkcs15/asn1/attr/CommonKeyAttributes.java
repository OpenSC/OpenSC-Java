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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.opensc.pkcs15.asn1.basic.KeyAccessFlags;
import org.opensc.pkcs15.asn1.basic.KeyUsageFlags;

/**
 * <PRE>
 * CommonKeyAttributes ::= SEQUENCE {
 *      iD                 Identifier,
 *      usage              KeyUsageFlags,
 *      native             BOOLEAN DEFAULT TRUE,
 *      accessFlags KeyAccessFlags OPTIONAL,
 *      keyReference Reference OPTIONAL,
 *      startDate          GeneralizedTime OPTIONAL,
 *      endDate            [0] GeneralizedTime OPTIONAL,
 *      ... -- For future extensions
 *      }
 * </PRE>
 * 
 * @author wglas
 */
public class CommonKeyAttributes extends ASN1Encodable {

    private ASN1OctetString iD;
    private KeyUsageFlags usage;
    private boolean nativeFlag;
    private KeyAccessFlags accessFlags;
    private BigInteger keyReference;
    private DERGeneralizedTime startDate;
    private DERGeneralizedTime endDate;
    
    /**
     * Default constructor.
     */
    public CommonKeyAttributes() {
        super();
        this.nativeFlag = true;
    }

    /**
     * @param obj The ASN.1 object to decode.
     * @return An instance of CommonObjectAttributes.
     */
    public static CommonKeyAttributes getInstance (Object obj)
    {
        if (obj instanceof CommonKeyAttributes)
            return (CommonKeyAttributes)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            CommonKeyAttributes ret = new CommonKeyAttributes();
            
            while (objs.hasMoreElements()) {
                
                Object o = objs.nextElement();
                
                if (o instanceof ASN1OctetString) {
                    ret.setID((ASN1OctetString)o);
                } else if (o instanceof DERBoolean) {
                    ret.setNativeFlag(((DERBoolean)o).isTrue());
                } else if (o instanceof DERInteger) {
                    ret.setKeyReference(((DERInteger)o).getValue());
                } else if (o instanceof DERBitString) {
                    if (ret.getUsage() == null)
                        ret.setUsage(KeyUsageFlags.getInstance(o));
                    else
                        ret.setAccessFlags(KeyAccessFlags.getInstance(o));
                } else if (o instanceof DERGeneralizedTime) {
                    ret.setStartDate((DERGeneralizedTime)o);
                } else if (o instanceof ASN1TaggedObject) {
                    
                    ASN1TaggedObject to = (ASN1TaggedObject)o;
                    
                    if (to.getTagNo() != 0)
                        throw new IllegalArgumentException("Invalid member tag ["+to.getTagNo()+"] in member of CommonKeyAttributes ASN.1 SEQUENCE.");
                    
                    ret.setEndDate(DERGeneralizedTime.getInstance(to.getObject()));
                        
                } else
                    throw new IllegalArgumentException("Invalid member ["+o+"] in CommonKeyAttributes ASN.1 SEQUENCE.");
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

        if (this.iD != null)
            v.add(this.iD);
        
        if (this.usage != null)
            v.add(this.usage);
        
        v.add(new DERBoolean(this.nativeFlag));
        
        if (this.accessFlags != null)
            v.add(this.accessFlags);
        
        if (this.keyReference != null)
            v.add(new DERInteger(this.keyReference));
        
        if (this.startDate != null)
            v.add(this.startDate);
        
        if (this.endDate != null)
            v.add(new DERTaggedObject(0,this.endDate));
        
        return new DERSequence(v);
    }

    /**
     * @return the iD
     */
    public ASN1OctetString getID() {
        return this.iD;
    }

    /**
     * @param id the iD to set
     */
    public void setID(ASN1OctetString id) {
        this.iD = id;
    }

    /**
     * @return the usage
     */
    public KeyUsageFlags getUsage() {
        return this.usage;
    }

    /**
     * @param usage the usage to set
     */
    public void setUsage(KeyUsageFlags usage) {
        this.usage = usage;
    }

    /**
     * @return the nativeFlag
     */
    public boolean isNativeFlag() {
        return this.nativeFlag;
    }

    /**
     * @param nativeFlag the nativeFlag to set
     */
    public void setNativeFlag(boolean nativeFlag) {
        this.nativeFlag = nativeFlag;
    }

    /**
     * @return the accessFlags
     */
    public KeyAccessFlags getAccessFlags() {
        return this.accessFlags;
    }

    /**
     * @param accessFlags the accessFlags to set
     */
    public void setAccessFlags(KeyAccessFlags accessFlags) {
        this.accessFlags = accessFlags;
    }

    /**
     * @return the keyReference
     */
    public BigInteger getKeyReference() {
        return this.keyReference;
    }

    /**
     * @param keyReference the keyReference to set
     */
    public void setKeyReference(BigInteger keyReference) {
        this.keyReference = keyReference;
    }

    /**
     * @return the startDate
     */
    public DERGeneralizedTime getStartDate() {
        return this.startDate;
    }

    /**
     * @param startDate the startDate to set
     */
    public void setStartDate(DERGeneralizedTime startDate) {
        this.startDate = startDate;
    }

    /**
     * @return the endDate
     */
    public DERGeneralizedTime getEndDate() {
        return this.endDate;
    }

    /**
     * @param endDate the endDate to set
     */
    public void setEndDate(DERGeneralizedTime endDate) {
        this.endDate = endDate;
    }

}
