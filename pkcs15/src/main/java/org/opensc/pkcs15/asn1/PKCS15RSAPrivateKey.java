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
 * privateRSAKey PrivateKeyObject {PrivateRSAKeyAttributes}
 * </PRE>
 * 
 * <PRE> 
 * PrivateKeyObject {KeyAttributes} ::= PKCS15Object {
 *       CommonKeyAttributes, CommonPrivateKeyAttributes, KeyAttributes}
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
public class PKCS15RSAPrivateKey extends ASN1Encodable {
    
    private CommonObjectAttributes commonObjectAttributes;
    private CommonKeyAttributes commonKeyAttributes;
    private CommonPrivateKeyAttributes commonPrivateKeyAttributes;
    private PrivateRSAKeyAttributes privateRSAKeyAttributes;
    
    /**
     * Default constructor.
     */
    public PKCS15RSAPrivateKey() {
    }
    
    /**
     * @param obj The ASN.1 object to decode.
     * @param keyKirectory The directory used to resolve referenced private key objects.
     * @param infoDirectory The directory used to resolve RSAKeyInfos.
     * @return An instance of CommonPrivateKeyAttributes.
     */
    public static PKCS15RSAPrivateKey getInstance (Object obj,
            Directory<Path, RSAPrivateKeyObject> keyKirectory,
            Directory<DERInteger, RSAKeyInfo> infoDirectory)
    {
        if (obj instanceof PKCS15RSAPrivateKey)
            return (PKCS15RSAPrivateKey)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            PKCS15RSAPrivateKey ret = new PKCS15RSAPrivateKey();
         
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing commonObjectAttributes member in PrivateRSAKey SEQUENCE.");

            ret.setCommonObjectAttributes(CommonObjectAttributes.getInstance(objs.nextElement()));
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing commonKeyAttributes member in PrivateRSAKey SEQUENCE.");

            ret.setCommonKeyAttributes(CommonKeyAttributes.getInstance(objs.nextElement()));
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing commonPrivateKeyAttributes member in PrivateRSAKey SEQUENCE.");

            ASN1TaggedObject to = ASN1TaggedObject.getInstance(objs.nextElement());
            
            if (to.getTagNo() == 0) {
                
                ret.setCommonPrivateKeyAttributes(CommonPrivateKeyAttributes.getInstance(objs.nextElement()));
                
                if (!objs.hasMoreElements())
                    throw new IllegalArgumentException("Missing privateRSAKeyAttributes member in PrivateRSAKey SEQUENCE.");
   
                to = ASN1TaggedObject.getInstance(objs.nextElement());
            }
            
            if (to.getTagNo() != 1)
                throw new IllegalArgumentException("Invalid tag ["+to.getTagNo()+"] in PrivateRSAKey SEQUENCE.");
            
            ret.setPrivateRSAKeyAttributes(PrivateRSAKeyAttributes.getInstance(to.getDERObject(),keyKirectory,infoDirectory));
               
            return ret;
        }
        
        throw new IllegalArgumentException("PrivateRSAKey must be encoded as an ASN.1 SEQUENCE.");
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

        if (this.commonPrivateKeyAttributes != null)
            v.add(new DERTaggedObject(0,this.commonPrivateKeyAttributes));

        if (this.privateRSAKeyAttributes != null)
            v.add(new DERTaggedObject(1,this.privateRSAKeyAttributes));

        return new DERSequence(v);
    }


    /**
     * @return the commonObjectAttributes
     */
    public CommonObjectAttributes getCommonObjectAttributes() {
        return this.commonObjectAttributes;
    }


    /**
     * @param commonObjectAttributes the commonObjectAttributes to set
     */
    public void setCommonObjectAttributes(
            CommonObjectAttributes commonObjectAttributes) {
        this.commonObjectAttributes = commonObjectAttributes;
    }


    /**
     * @return the commonKeyAttributes
     */
    public CommonKeyAttributes getCommonKeyAttributes() {
        return this.commonKeyAttributes;
    }


    /**
     * @param commonKeyAttributes the commonKeyAttributes to set
     */
    public void setCommonKeyAttributes(CommonKeyAttributes commonKeyAttributes) {
        this.commonKeyAttributes = commonKeyAttributes;
    }


    /**
     * @return the commonPrivateKeyAttributes
     */
    public CommonPrivateKeyAttributes getCommonPrivateKeyAttributes() {
        return this.commonPrivateKeyAttributes;
    }


    /**
     * @param commonPrivateKeyAttributes the commonPrivateKeyAttributes to set
     */
    public void setCommonPrivateKeyAttributes(
            CommonPrivateKeyAttributes commonPrivateKeyAttributes) {
        this.commonPrivateKeyAttributes = commonPrivateKeyAttributes;
    }


    /**
     * @return the privateRSAKeyAttributes
     */
    public PrivateRSAKeyAttributes getPrivateRSAKeyAttributes() {
        return this.privateRSAKeyAttributes;
    }


    /**
     * @param privateRSAKeyAttributes the privateRSAKeyAttributes to set
     */
    public void setPrivateRSAKeyAttributes(
            PrivateRSAKeyAttributes privateRSAKeyAttributes) {
        this.privateRSAKeyAttributes = privateRSAKeyAttributes;
    }

    
    

}
