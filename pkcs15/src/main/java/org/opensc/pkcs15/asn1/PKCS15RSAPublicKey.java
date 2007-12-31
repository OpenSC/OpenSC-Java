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
 * Created: 29.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <PRE>
 * publicRSAKey PublicKeyObject {PublicRSAKeyAttributes}
 * </PRE>
 * 
 * <PRE> 
 * PublicKeyObject {KeyAttributes} ::= PKCS15Object {
 *       CommonKeyAttributes, CommonPublicKeyAttributes, KeyAttributes}
 * </PRE>
 * 
 * <PRE> 
 * PKCS15Object {ClassAttributes, SubClassAttributes, TypeAttributes} ::= SEQUENCE {
 *       commonObjectAttributes CommonObjectAttributes,
 *       classAttributes      ClassAttributes,
 *       subClassAttributes         [0] SubClassAttributes OPTIONAL,
 *       typeAttributes       [1] TypeAttributes
 *       }
 * </PRE>
 * 
 * @author wglas
 *
 */
public class PKCS15RSAPublicKey extends ASN1Encodable implements PKCS15PublicKey {
    
    private CommonObjectAttributes commonObjectAttributes;
    private CommonKeyAttributes commonKeyAttributes;
    private CommonPublicKeyAttributes commonPublicKeyAttributes;
    private PublicRSAKeyAttributes publicRSAKeyAttributes;
    
    /**
     * Default constructor.
     */
    public PKCS15RSAPublicKey() {
    }
    
    /**
     * @param obj The ASN.1 object to decode.
     * @param keyKirectory The directory used to resolve referenced public key objects.
     * @param infoDirectory The directory used to resolve RSAKeyInfos.
     * @return An instance of PKCS15RSAPublicKey.
     */
    public static PKCS15PublicKey getInstance (Object obj,
            Directory<Path, RSAPublicKeyObject> keyKirectory,
            Directory<DERInteger, RSAKeyInfo> infoDirectory)
    {
        if (obj instanceof PKCS15RSAPublicKey)
            return (PKCS15PublicKey)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            PKCS15RSAPublicKey ret = new PKCS15RSAPublicKey();
         
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing commonObjectAttributes member in PublicRSAKey SEQUENCE.");

            ret.setCommonObjectAttributes(CommonObjectAttributes.getInstance(objs.nextElement()));
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing commonKeyAttributes member in PublicRSAKey SEQUENCE.");

            ret.setCommonKeyAttributes(CommonKeyAttributes.getInstance(objs.nextElement()));
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing commonPublicKeyAttributes member in PublicRSAKey SEQUENCE.");

            ASN1TaggedObject to = ASN1TaggedObject.getInstance(objs.nextElement());
            
            if (to.getTagNo() == 0) {
                
                ret.setCommonPublicKeyAttributes(CommonPublicKeyAttributes.getInstance(objs.nextElement()));
                
                if (!objs.hasMoreElements())
                    throw new IllegalArgumentException("Missing publicRSAKeyAttributes member in PublicRSAKey SEQUENCE.");
   
                to = ASN1TaggedObject.getInstance(objs.nextElement());
            }
            
            if (to.getTagNo() != 1)
                throw new IllegalArgumentException("Invalid tag ["+to.getTagNo()+"] in PublicRSAKey SEQUENCE.");
            
            ret.setPublicRSAKeyAttributes(PublicRSAKeyAttributes.getInstance(to.getDERObject(),keyKirectory,infoDirectory));
               
            return ret;
        }
        
        throw new IllegalArgumentException("PublicRSAKey must be encoded as an ASN.1 SEQUENCE.");
    }

    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (this.commonObjectAttributes != null)
            v.add(this.commonObjectAttributes);
        
        if (this.commonKeyAttributes != null)
            v.add(this.commonKeyAttributes);

        if (this.commonPublicKeyAttributes != null)
            v.add(new DERTaggedObject(0,this.commonPublicKeyAttributes));

        if (this.publicRSAKeyAttributes != null)
            v.add(new DERTaggedObject(1,this.publicRSAKeyAttributes));

        return new DERSequence(v);
    }


    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.PKCS15PublicKey#getCommonObjectAttributes()
     */
    public CommonObjectAttributes getCommonObjectAttributes() {
        return this.commonObjectAttributes;
    }


    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.PKCS15PublicKey#setCommonObjectAttributes(org.opensc.pkcs15.asn1.CommonObjectAttributes)
     */
    public void setCommonObjectAttributes(
            CommonObjectAttributes commonObjectAttributes) {
        this.commonObjectAttributes = commonObjectAttributes;
    }


    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.PKCS15PublicKey#getCommonKeyAttributes()
     */
    public CommonKeyAttributes getCommonKeyAttributes() {
        return this.commonKeyAttributes;
    }


    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.PKCS15PublicKey#setCommonKeyAttributes(org.opensc.pkcs15.asn1.CommonKeyAttributes)
     */
    public void setCommonKeyAttributes(CommonKeyAttributes commonKeyAttributes) {
        this.commonKeyAttributes = commonKeyAttributes;
    }


    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.PKCS15PublicKey#getCommonPublicKeyAttributes()
     */
    public CommonPublicKeyAttributes getCommonPublicKeyAttributes() {
        return this.commonPublicKeyAttributes;
    }


    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.PKCS15PublicKey#setCommonPublicKeyAttributes(org.opensc.pkcs15.asn1.CommonPublicKeyAttributes)
     */
    public void setCommonPublicKeyAttributes(
            CommonPublicKeyAttributes commonPublicKeyAttributes) {
        this.commonPublicKeyAttributes = commonPublicKeyAttributes;
    }


    /**
     * @return the publicRSAKeyAttributes
     */
    public PublicRSAKeyAttributes getPublicRSAKeyAttributes() {
        return this.publicRSAKeyAttributes;
    }


    /**
     * @param publicRSAKeyAttributes the publicRSAKeyAttributes to set
     */
    public void setPublicRSAKeyAttributes(
            PublicRSAKeyAttributes publicRSAKeyAttributes) {
        this.publicRSAKeyAttributes = publicRSAKeyAttributes;
    }

}
