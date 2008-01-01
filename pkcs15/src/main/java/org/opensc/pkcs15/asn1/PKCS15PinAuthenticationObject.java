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
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.opensc.pkcs15.asn1.attr.CommonAuthenticationObjectAttributes;
import org.opensc.pkcs15.asn1.attr.CommonObjectAttributes;
import org.opensc.pkcs15.asn1.attr.PinAttributes;

/**
 * <PRE>
 * pin   AuthenticationObject { PinAttributes }
 * </PRE>
 * 
 * <PRE> 
 * AuthenticationObject {AuthObjectAttributes} ::= PKCS15Object {
 *         CommonAuthenticationObjectAttributes, NULL, AuthObjectAttributes}
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
public class PKCS15PinAuthenticationObject extends PKCS15AuthenticationObject {
    
    private PinAttributes pinAttributes;
    
    /**
     * Default constructor.
     */
    public PKCS15PinAuthenticationObject() {
    }
    
    /**
     * This method implements the static getInstance factory pattern. 
     * 
     * @param obj ASN.1 object to be decoded.
     * @return A PKCS15PinAuthenticationObject instance.
     */
    public static PKCS15PinAuthenticationObject getInstance (Object obj)
    {
        if (obj instanceof PKCS15PinAuthenticationObject)
            return (PKCS15PinAuthenticationObject)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            PKCS15PinAuthenticationObject ret = new PKCS15PinAuthenticationObject();
         
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing commonObjectAttributes member in PinAuthenticationObject SEQUENCE.");

            ret.setCommonObjectAttributes(CommonObjectAttributes.getInstance(objs.nextElement()));
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing commonPublicKeyAttributes member in PinAuthenticationObject SEQUENCE.");

            ret.setCommonAuthenticationObjectAttributes(CommonAuthenticationObjectAttributes.getInstance(objs.nextElement()));
                
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing pinAttributes member in PinAuthenticationObject SEQUENCE.");
            
            ASN1TaggedObject to = ASN1TaggedObject.getInstance(objs.nextElement());

            if (to.getTagNo() != 1)
                throw new IllegalArgumentException("Invalid tag ["+to.getTagNo()+"] in PinAuthenticationObject SEQUENCE.");
            
            ret.setPinAttributes(PinAttributes.getInstance(to.getDERObject()));
               
            return ret;
        }
        
        throw new IllegalArgumentException("PinAuthenticationObject must be encoded as an ASN.1 SEQUENCE.");
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (this.getCommonObjectAttributes() != null)
            v.add(this.getCommonObjectAttributes());
        
        if (this.getCommonAuthenticationObjectAttributes() != null)
            v.add(this.getCommonAuthenticationObjectAttributes());

        if (this.pinAttributes != null)
            v.add(new DERTaggedObject(1,this.pinAttributes));

        return new DERSequence(v);
    }

    /**
     * @return the pinAttributes
     */
    public PinAttributes getPinAttributes() {
        return this.pinAttributes;
    }

    /**
     * @param pinAttributes the pinAttributes to set
     */
    public void setPinAttributes(
            PinAttributes pinAttributes) {
        this.pinAttributes = pinAttributes;
    }

}
