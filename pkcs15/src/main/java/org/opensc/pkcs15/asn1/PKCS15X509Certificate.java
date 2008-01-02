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
import org.opensc.pkcs15.asn1.attr.CommonCertificateAttributes;
import org.opensc.pkcs15.asn1.attr.CommonObjectAttributes;
import org.opensc.pkcs15.asn1.attr.X509CertificateAttributes;
import org.opensc.pkcs15.asn1.attr.X509CertificateObject;
import org.opensc.pkcs15.asn1.proxy.Directory;
import org.opensc.pkcs15.asn1.ref.Path;

/**
 * <PRE>
 * x509Certificate CertificateObject {X509CertificateAttributes}
 * </PRE>
 * 
 * <PRE> 
 *  CertificateObject {CertAttributes} ::= PKCS15Object {
 *          CommonCertificateAttributes, NULL, CertAttributes}
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
public class PKCS15X509Certificate extends PKCS15Certificate {
    
    private X509CertificateAttributes x509CertificateAttributes;
    
    /**
     * Default constructor.
     */
    public PKCS15X509Certificate() {
    }
    
    /**
     * This method implements the static getInstance factory pattern by
     * using the thread-local context stored in {@link ContextHolder}. 
     * 
     * @param obj ASN.1 object to be decoded.
     * @return A PKCS15X509Certificate object suitable for RSA Private keys.
     */
    static public PKCS15X509Certificate getInstance(Object obj)
    {
        Context context = ContextHolder.getContext();
        
         Directory<Path, X509CertificateObject> keyKirectory =
            context == null ? null : context.getX509CertificateDirectory();
        
        return getInstance(obj,keyKirectory);
    }

    /**
     * @param obj The ASN.1 object to decode.
     * @param keyKirectory The directory used to resolve referenced public key objects.
     * @param infoDirectory The directory used to resolve X509CertificateObjects.
     * @return An instance of PKCS15X509Certificate.
     */
    public static PKCS15X509Certificate getInstance (Object obj,
            Directory<Path, X509CertificateObject> keyKirectory)
    {
        if (obj instanceof PKCS15X509Certificate)
            return (PKCS15X509Certificate)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            PKCS15X509Certificate ret = new PKCS15X509Certificate();
         
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing commonObjectAttributes member in X509Certificate SEQUENCE.");

            ret.setCommonObjectAttributes(CommonObjectAttributes.getInstance(objs.nextElement()));
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing commonPublicKeyAttributes member in X509Certificate SEQUENCE.");

            ret.setCommonCertificateAttributes(CommonCertificateAttributes.getInstance(objs.nextElement()));
                
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing x509CertificateAttributes member in X509Certificate SEQUENCE.");
            
            ASN1TaggedObject to = ASN1TaggedObject.getInstance(objs.nextElement());

            if (to.getTagNo() != 1)
                throw new IllegalArgumentException("Invalid tag ["+to.getTagNo()+"] in X509Certificate SEQUENCE.");
            
            ret.setX509CertificateAttributes(X509CertificateAttributes.getInstance(to.getObject(),keyKirectory));
               
            return ret;
        }
        
        throw new IllegalArgumentException("X509Certificate must be encoded as an ASN.1 SEQUENCE.");
    }

    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (this.getCommonObjectAttributes() != null)
            v.add(this.getCommonObjectAttributes());
        
        if (this.getCommonCertificateAttributes() != null)
            v.add(this.getCommonCertificateAttributes());

        if (this.x509CertificateAttributes != null)
            v.add(new DERTaggedObject(1,this.x509CertificateAttributes));

        return new DERSequence(v);
    }

    /**
     * @return the x509CertificateAttributes
     */
    public X509CertificateAttributes getX509CertificateAttributes() {
        return this.x509CertificateAttributes;
    }


    /**
     * @param x509CertificateAttributes the x509CertificateAttributes to set
     */
    public void setX509CertificateAttributes(
            X509CertificateAttributes x509CertificateAttributes) {
        this.x509CertificateAttributes = x509CertificateAttributes;
    }

}
