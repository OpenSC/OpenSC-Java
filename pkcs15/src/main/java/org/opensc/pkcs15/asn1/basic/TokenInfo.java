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

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.opensc.pkcs15.asn1.helper.IntegerHelper;

/**
 * <PRE>
 * TokenInfo ::= SEQUENCE {
 *        version                  INTEGER {v1(0)} (v1,...),
 *        serialNumber             OCTET STRING,
 *        manufacturerID           Label OPTIONAL,
 *        label                    [0] Label OPTIONAL,
 *        tokenflags               TokenFlags,
 *        seInfo                   SEQUENCE OF SecurityEnvironmentInfo OPTIONAL,
 *        recordInfo               [1] RecordInfo OPTIONAL,
 *        supportedAlgorithms[2] SEQUENCE OF AlgorithmInfo OPTIONAL,
 *        ...,
 *        issuerId                 [3] Label OPTIONAL,
 *        holderId                 [4] Label OPTIONAL,
 *        lastUpdate               [5] LastUpdate OPTIONAL,
 *        preferredLanguage        PrintableString OPTIONAL – In accordance with IETF RFC 1766
 *        } (CONSTRAINED BY { -- Each AlgorithmInfo.reference value must be unique --})
 * </PRE>
 * 
 * @author wglas
 */
public class TokenInfo extends ASN1Encodable {

    private byte[] serialNumber;
    private String manufacturerID;
    private String label;
    private TokenFlags tokenflags;
    private List<SecurityEnvironmentInfo> seInfo;
    private RecordInfo recordInfo;
    private SortedMap<Integer,AlgorithmInfo> supportedAlgorithms;
    private String issuerId;
    private String holderId;
    private GeneralizedTimeHolder lastUpdate;
    private String preferredLanguage;
    
    /**
     * Default constructor.
     */
    public TokenInfo() {
        super();
    }
    
    /**
     * @param obj The ASN.1 object to decode.
     * @return A TokenInfo instance.
     */
    public static TokenInfo getInstance (Object obj)
    {
        if (obj instanceof TokenInfo)
            return (TokenInfo)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing version member in TokenInfo SEQUENCE.");
            
            Object o = objs.nextElement();
            
            int version = IntegerHelper.intValue(DERInteger.getInstance(o).getValue());
            
            if (version != 0)
                throw new IllegalArgumentException("Unsupported version ["+version+"] in TokenInfo SEQUENCE.");
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing serialNumber member in TokenInfo SEQUENCE.");
            
            TokenInfo ret = new TokenInfo();
            
            o = objs.nextElement();
            ret.setSerialNumber(ASN1OctetString.getInstance(o).getOctets());

            if (!objs.hasMoreElements()) return ret;
            o = objs.nextElement();
                
            if (o instanceof DERUTF8String) {
                
                ret.setManufacturerID(DERUTF8String.getInstance(o).getString());
                
                if (!objs.hasMoreElements()) return ret;
                o = objs.nextElement();    
            }
            
            if (o instanceof ASN1TaggedObject && ((ASN1TaggedObject)o).getTagNo() == 0) {
                
                ret.setLabel(DERUTF8String.getInstance(((ASN1TaggedObject)o).getObject()).getString());
                
                if (!objs.hasMoreElements()) return ret;
                o = objs.nextElement();    
            }
            
            if (!(o instanceof DERBitString))
                throw new IllegalArgumentException("Missing tokenFlags member in TokenInfo SEQUENCE.");

            ret.setTokenflags(TokenFlags.getInstance(o));
            
            if (!objs.hasMoreElements()) return ret;
            o = objs.nextElement();    
            
            if (o instanceof ASN1Sequence) {
                
                ASN1Sequence seseq = ASN1Sequence.getInstance(o);
                
                Enumeration<Object> seobjs = seseq.getObjects();
                
                while (seobjs.hasMoreElements())
                {
                    ret.addSeInfo(SecurityEnvironmentInfo.getInstance(seobjs.nextElement()));
                }
                
                if (!objs.hasMoreElements()) return ret;
                o = objs.nextElement();    
            }
            
            if (o instanceof ASN1TaggedObject && ((ASN1TaggedObject)o).getTagNo() == 1) {
                
                ret.setRecordInfo(RecordInfo.getInstance(((ASN1TaggedObject)o).getObject()));
                
                if (!objs.hasMoreElements()) return ret;
                o = objs.nextElement();    
            }

            if (o instanceof ASN1TaggedObject && ((ASN1TaggedObject)o).getTagNo() == 2) {
                
                ASN1Sequence aiseq = ASN1Sequence.getInstance(((ASN1TaggedObject)o).getObject());
                
                Enumeration<Object> aiobjs = aiseq.getObjects();
                
                while (aiobjs.hasMoreElements())
                {
                    ret.addSupportedAlgorithm(AlgorithmInfo.getInstance(aiobjs.nextElement()));
                }
                  
                if (!objs.hasMoreElements()) return ret;
                o = objs.nextElement();    
            }

            if (o instanceof ASN1TaggedObject && ((ASN1TaggedObject)o).getTagNo() == 3) {
                
                ret.setIssuerId(DERUTF8String.getInstance(((ASN1TaggedObject)o).getObject()).getString());
                
                if (!objs.hasMoreElements()) return ret;
                o = objs.nextElement();    
            }
            
            if (o instanceof ASN1TaggedObject && ((ASN1TaggedObject)o).getTagNo() == 4) {
                
                ret.setHolderId(DERUTF8String.getInstance(((ASN1TaggedObject)o).getObject()).getString());
    
                if (!objs.hasMoreElements()) return ret;
                o = objs.nextElement();    
            }

            if (o instanceof ASN1TaggedObject && ((ASN1TaggedObject)o).getTagNo() == 5) {
                
                ret.setLastUpdate(GeneralizedTimeHolderImpl.getInstance(((ASN1TaggedObject)o).getObject()));
                
                if (!objs.hasMoreElements()) return ret;
                o = objs.nextElement();    
            }

            ret.setPreferredLanguage(DERPrintableString.getInstance(o).getString());
            
            return ret;
        }
        
        throw new IllegalArgumentException("AccessControlRule must be encoded as an ASN.1 SEQUENCE.");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERInteger(0));
        v.add(new DEROctetString(this.getSerialNumber()));
        
        if (this.getManufacturerID() != null)
            v.add(new DERUTF8String(this.getManufacturerID()));
            
        if (this.getLabel() != null)
            v.add(new DERTaggedObject(0,new DERUTF8String(this.getLabel())));
        
        v.add(this.getTokenflags());
        
        if (this.getSeInfo() != null) {
            
            ASN1EncodableVector vse = new ASN1EncodableVector();
    
            for (SecurityEnvironmentInfo si : this.getSeInfo())
                vse.add(si);
                
            v.add(new DERSequence(vse));
        }
        
        if (this.getRecordInfo() != null)
            v.add(new DERTaggedObject(1,this.getRecordInfo()));
        
        if (this.getSupportedAlgotihms() != null) {
            
            ASN1EncodableVector vai = new ASN1EncodableVector();
    
            for (AlgorithmInfo ai : this.getSupportedAlgotihms().values())
                vai.add(ai);
                
            v.add(new DERTaggedObject(2,new DERSequence(vai)));
        }

        if (this.getIssuerId() != null)
            v.add(new DERTaggedObject(3,new DERUTF8String(this.getIssuerId())));
        
        if (this.getHolderId() != null)
            v.add(new DERTaggedObject(4,new DERUTF8String(this.getHolderId())));
        
        if (this.getLastUpdate() != null)
            v.add(new DERTaggedObject(5,this.getLastUpdate()));
        
        if (this.getPreferredLanguage() != null)
            v.add(new DERPrintableString(this.getPreferredLanguage()));

        return new DERSequence(v);
    }

    /**
     * @return the serialNumber
     */
    public byte[] getSerialNumber() {
        return this.serialNumber;
    }

    /**
     * @param serialNumber the serialNumber to set
     */
    public void setSerialNumber(byte[] serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * @return the manufacturerID
     */
    public String getManufacturerID() {
        return this.manufacturerID;
    }

    /**
     * @param manufacturerID the manufacturerID to set
     */
    public void setManufacturerID(String manufacturerID) {
        this.manufacturerID = manufacturerID;
    }

    /**
     * @return the label
     */
    public String getLabel() {
        return this.label;
    }

    /**
     * @param label the label to set
     */
    public void setLabel(String label) {
        this.label = label;
    }

    /**
     * @return the tokenflags
     */
    public TokenFlags getTokenflags() {
        return this.tokenflags;
    }

    /**
     * @param tokenflags the tokenflags to set
     */
    public void setTokenflags(TokenFlags tokenflags) {
        this.tokenflags = tokenflags;
    }

    /**
     * @return the seInfo
     */
    public List<SecurityEnvironmentInfo> getSeInfo() {
        return this.seInfo;
    }

    /**
     * @param seInfo the seInfo to set
     */
    public void setSeInfo(List<SecurityEnvironmentInfo> seInfo) {
        this.seInfo = seInfo;
    }

    /**
     * @param seInfo1
     */
    public void addSeInfo(SecurityEnvironmentInfo seInfo1) {
        if (this.seInfo == null)
            this.seInfo = new ArrayList<SecurityEnvironmentInfo>();
        
        this.seInfo.add(seInfo1);
    }

    /**
     * @return the recordInfo
     */
    public RecordInfo getRecordInfo() {
        return this.recordInfo;
    }

    /**
     * @param recordInfo the recordInfo to set
     */
    public void setRecordInfo(RecordInfo recordInfo) {
        this.recordInfo = recordInfo;
    }

    /**
     * @return the supportedAlgorithms
     */
    public SortedMap<Integer, AlgorithmInfo> getSupportedAlgotihms() {
        return this.supportedAlgorithms;
    }

    /**
     * @param supportedAlgotihms the supportedAlgotihms to set
     */
    public void setSupportedAlgorithms(
            SortedMap<Integer, AlgorithmInfo> supportedAlgorithms) {
        this.supportedAlgorithms = supportedAlgorithms;
    }

    /**
     * @param ai
     */
    public void addSupportedAlgorithm(AlgorithmInfo ai) {
        
        if (this.supportedAlgorithms == null)
            this.supportedAlgorithms = new TreeMap<Integer, AlgorithmInfo>();
        
        if (this.supportedAlgorithms.containsKey(ai.getReference()))
            throw new IllegalArgumentException("Duplicate algorithm reference ["+ai.getReference()+"].");
        
        this.supportedAlgorithms.put(ai.getReference(),ai);
    }
    
    /**
     * @return the issuerId
     */
    public String getIssuerId() {
        return this.issuerId;
    }

    /**
     * @param issuerId the issuerId to set
     */
    public void setIssuerId(String issuerId) {
        this.issuerId = issuerId;
    }

    /**
     * @return the holderId
     */
    public String getHolderId() {
        return this.holderId;
    }

    /**
     * @param holderId the holderId to set
     */
    public void setHolderId(String holderId) {
        this.holderId = holderId;
    }

    /**
     * @return the lastUpdate
     */
    public GeneralizedTimeHolder getLastUpdate() {
        return this.lastUpdate;
    }

    /**
     * @param lastUpdate the lastUpdate to set
     */
    public void setLastUpdate(GeneralizedTimeHolder lastUpdate) {
        this.lastUpdate = lastUpdate;
    }

    /**
     * @return the preferredLanguage
     */
    public String getPreferredLanguage() {
        return this.preferredLanguage;
    }

    /**
     * @param preferredLanguage the preferredLanguage to set
     */
    public void setPreferredLanguage(String preferredLanguage) {
        this.preferredLanguage = preferredLanguage;
    }

}
