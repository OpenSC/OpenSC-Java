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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.opensc.pkcs15.asn1.attr.CommonKeyAttributes;
import org.opensc.pkcs15.asn1.attr.CommonObjectAttributes;
import org.opensc.pkcs15.asn1.attr.CommonPrivateKeyAttributes;
import org.opensc.pkcs15.asn1.attr.PrivateRSAKeyAttributes;
import org.opensc.pkcs15.asn1.attr.RSAPrivateKeyObject;
import org.opensc.pkcs15.asn1.attr.SpecificPrivateKeyAttributes;
import org.opensc.pkcs15.asn1.basic.RSAKeyInfo;
import org.opensc.pkcs15.asn1.proxy.Directory;
import org.opensc.pkcs15.asn1.ref.Path;

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
public class PKCS15RSAPrivateKey extends PKCS15PrivateKey {
    
    private PrivateRSAKeyAttributes privateRSAKeyAttributes;
    
    /**
     * Default constructor.
     */
    public PKCS15RSAPrivateKey() {
    }
    
    /**
     * This method implements the static getInstance factory pattern by
     * using the thread-local context stored in {@link ContextHolder}. 
     * 
     * @param obj ASN.1 object to be decoded.
     * @return A KeyInfo object suitable for RSA Private keys.
     */
    static public PKCS15PrivateKey getInstance(Object obj)
    {
        Context context = ContextHolder.getContext();
        
        Directory<DERInteger,RSAKeyInfo> infoDirectory =
            context == null ? null : context.getRSAKeyInfoDirectory();
        
        Directory<Path, RSAPrivateKeyObject> keyKirectory =
            context == null ? null : context.getRSAPrivateKeyDirectory();
        
        return getInstance(obj,keyKirectory,infoDirectory);
    }

    /**
     * @param obj The ASN.1 object to decode.
     * @param keyKirectory The directory used to resolve referenced private key objects.
     * @param infoDirectory The directory used to resolve RSAKeyInfos.
     * @return An instance of CommonPrivateKeyAttributes.
     */
    public static PKCS15PrivateKey getInstance (Object obj,
            Directory<Path, RSAPrivateKeyObject> keyKirectory,
            Directory<DERInteger, RSAKeyInfo> infoDirectory)
    {
        if (obj instanceof PKCS15RSAPrivateKey)
            return (PKCS15PrivateKey)obj;
            
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
                
                ret.setCommonPrivateKeyAttributes(CommonPrivateKeyAttributes.getInstance(to.getObject()));
                
                if (!objs.hasMoreElements())
                    throw new IllegalArgumentException("Missing privateRSAKeyAttributes member in PrivateRSAKey SEQUENCE.");
   
                to = ASN1TaggedObject.getInstance(objs.nextElement());
            }
            
            if (to.getTagNo() != 1)
                throw new IllegalArgumentException("Invalid tag ["+to.getTagNo()+"] in PrivateRSAKey SEQUENCE.");
            
            ret.setPrivateRSAKeyAttributes(PrivateRSAKeyAttributes.getInstance(to.getObject(),keyKirectory,infoDirectory));
               
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

        if (this.getCommonObjectAttributes() != null)
            v.add(this.getCommonObjectAttributes());
        
        if (this.getCommonKeyAttributes() != null)
            v.add(this.getCommonKeyAttributes());

        if (this.getCommonPrivateKeyAttributes() != null)
            v.add(new DERTaggedObject(0,this.getCommonPrivateKeyAttributes()));

        if (this.privateRSAKeyAttributes != null)
            v.add(new DERTaggedObject(1,this.privateRSAKeyAttributes));

        return new DERSequence(v);
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

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.PKCS15PrivateKey#getSpecificPrivateKeyAttributes()
     */
    @Override
    public SpecificPrivateKeyAttributes getSpecificPrivateKeyAttributes() {
        
        return this.privateRSAKeyAttributes;
    }
}
