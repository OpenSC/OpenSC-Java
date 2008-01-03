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
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.opensc.pkcs15.asn1.basic.PinFlags;
import org.opensc.pkcs15.asn1.basic.PinType;
import org.opensc.pkcs15.asn1.helper.IntegerHelper;
import org.opensc.pkcs15.asn1.ref.Path;

/**
 * <PRE>
 * PinAttributes ::= SEQUENCE {
 *          pinFlags           PinFlags,
 *          pinType PinType,
 *          minLength          INTEGER (pkcs15-lb-minPinLength..pkcs15-ub-minPinLength),
 *          storedLength INTEGER (0..pkcs15-ub-storedPinLength),
 *          maxLength          INTEGER OPTIONAL,
 *          pinReference [0] Reference DEFAULT 0,
 *          padChar            OCTET STRING (SIZE(1)) OPTIONAL,
 *          lastPinChange GeneralizedTime OPTIONAL,
 *          path               Path OPTIONAL,
 *          ... -- For future extensions
 *          }
 * </PRE>
 * 
 * @author wglas
 */
public class PinAttributes extends ASN1Encodable {

    private PinFlags pinFlags;
    private PinType pinType;
    private int minLength;
    private int storedLength;
    private Integer maxLength;
    private Integer pinReference;
    private Byte padChar;
    private DERGeneralizedTime lastPinChange;
    private Path path;
    
    /**
     * Default constructor.
     */
    public PinAttributes() {
        super();
    }

    /**
     * @param obj The ASN.1 object to decode.
     * @return An instance of CommonObjectAttributes.
     */
    /**
     * @param obj
     * @return
     */
    public static PinAttributes getInstance (Object obj)
    {
        if (obj instanceof PinAttributes)
            return (PinAttributes)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            PinAttributes ret = new PinAttributes();
            
            Object o = objs.nextElement();
            ret.setPinFlags(PinFlags.getInstance(o));
            o = objs.nextElement();
            ret.setPinType(PinType.getInstance(o));
            o = objs.nextElement();
            ret.setMinLength(IntegerHelper.intValue(DERInteger.getInstance(o).getValue()));
            o = objs.nextElement();
            ret.setStoredLength(IntegerHelper.intValue(DERInteger.getInstance(o).getValue()));
            
            if (!objs.hasMoreElements()) return ret;
            
            o = objs.nextElement();
            
            if (o instanceof DERInteger) {
                
                ret.setMaxLength(IntegerHelper.toInteger(DERInteger.getInstance(o).getValue()));
                
                if (!objs.hasMoreElements()) return ret;
                o = objs.nextElement();
             }
            
           if (o instanceof ASN1TaggedObject) {
               
               ASN1TaggedObject to = (ASN1TaggedObject)o;
               
               if (to.getTagNo() != 0)
                   throw new IllegalArgumentException("Invalid member tag ["+to.getTagNo()+"] in member of PinAttributes ASN.1 SEQUENCE.");
               
               ret.setPinReference(IntegerHelper.toInteger(DERInteger.getInstance(to.getObject()).getValue()));
                
               if (!objs.hasMoreElements()) return ret;
               o = objs.nextElement();
           }
               
            
           if (o instanceof ASN1OctetString) {
               
               ret.setPadChar(new Byte(ASN1OctetString.getInstance(o).getOctets()[0]));
               
               if (!objs.hasMoreElements()) return ret;
               o = objs.nextElement();
            }
          
           if (o instanceof DERGeneralizedTime) {
               
               ret.setLastPinChange(DERGeneralizedTime.getInstance(o));
               
               if (!objs.hasMoreElements()) return ret;
               o = objs.nextElement();
           }
          
           ret.setPath(Path.getInstance(o));
               
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

        if (this.pinFlags != null)
            v.add(this.pinFlags);
        
        if (this.pinType != null)
            v.add(this.pinType);
        
        v.add(new DERInteger(this.minLength));
        v.add(new DERInteger(this.storedLength));
        if (this.maxLength != null)
            v.add(new DERInteger(this.maxLength.intValue()));
        
        if (this.pinReference != null)
            v.add(new DERTaggedObject(0,new DERInteger(this.pinReference)));
       
        if (this.padChar != null)
            v.add(new DEROctetString(new byte[] {this.padChar.byteValue()}));
        
        if (this.lastPinChange != null)
            v.add(this.lastPinChange);
        
        if (this.path != null)
            v.add(this.path);
        
        return new DERSequence(v);
    }

    /**
     * @return the pinFlags
     */
    public PinFlags getPinFlags() {
        return this.pinFlags;
    }

    /**
     * @param pinFlags the pinFlags to set
     */
    public void setPinFlags(PinFlags pinFlags) {
        this.pinFlags = pinFlags;
    }

    /**
     * @return the pinType
     */
    public PinType getPinType() {
        return this.pinType;
    }

    /**
     * @param pinType the pinType to set
     */
    public void setPinType(PinType pinType) {
        this.pinType = pinType;
    }

    /**
     * @return the minLength
     */
    public int getMinLength() {
        return this.minLength;
    }

    /**
     * @param minLength the minLength to set
     */
    public void setMinLength(int minLength) {
        this.minLength = minLength;
    }

    /**
     * @return the storedLength
     */
    public int getStoredLength() {
        return this.storedLength;
    }

    /**
     * @param storedLength the storedLength to set
     */
    public void setStoredLength(int storedLength) {
        this.storedLength = storedLength;
    }

    /**
     * @return the maxLength
     */
    public Integer getMaxLength() {
        return this.maxLength;
    }

    /**
     * @param maxLength the maxLength to set
     */
    public void setMaxLength(Integer maxLength) {
        this.maxLength = maxLength;
    }

    /**
     * @return the pinReference
     */
    public Integer getPinReference() {
        return this.pinReference;
    }

    /**
     * @param pinReference the pinReference to set
     */
    public void setPinReference(Integer pinReference) {
        this.pinReference = pinReference;
    }

    /**
     * @return the padChar
     */
    public Byte getPadChar() {
        return this.padChar;
    }

    /**
     * @param padChar the padChar to set
     */
    public void setPadChar(Byte padChar) {
        this.padChar = padChar;
    }

    /**
     * @return the lastPinChange
     */
    public DERGeneralizedTime getLastPinChange() {
        return this.lastPinChange;
    }

    /**
     * @param lastPinChange the lastPinChange to set
     */
    public void setLastPinChange(DERGeneralizedTime lastPinChange) {
        this.lastPinChange = lastPinChange;
    }

    /**
     * @return the path
     */
    public Path getPath() {
        return this.path;
    }

    /**
     * @param path the path to set
     */
    public void setPath(Path path) {
        this.path = path;
    }
}
