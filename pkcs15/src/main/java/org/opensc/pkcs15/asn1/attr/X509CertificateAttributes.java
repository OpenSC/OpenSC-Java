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
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.X509Name;
import org.opensc.pkcs15.asn1.Context;
import org.opensc.pkcs15.asn1.ContextHolder;
import org.opensc.pkcs15.asn1.proxy.Directory;
import org.opensc.pkcs15.asn1.ref.Path;

/**
 * <PRE>
 *  X509CertificateAttributes ::= SEQUENCE {
 *        value              ObjectValue { Certificate },
 *        subject            Name OPTIONAL,
 *        issuer             [0] Name OPTIONAL,
 *        serialNumber CertificateSerialNumber OPTIONAL,
 *        ... -- For future extensions
 *        }
 * </PRE>
 * 
 * @author wglas
 */
public class X509CertificateAttributes extends ASN1Encodable implements SpecificCertificateAttributes {

    private X509CertificateObject value;
    private X509Name subject;
    private X509Name issuer;
    private BigInteger serialNumber;
    
    /**
     * Default constructor.
     */
    public X509CertificateAttributes() {
        super();
    }

    /**
     * This factory method uses the thread-bound context hold in {@link ContextHolder}
     * in order to resolve references.
     * 
     * @param obj The ASN.1 object to decode.
     * @return An instance of CommonPublicKeyAttributes.
     */
    public static X509CertificateAttributes getInstance (Object obj)
    {
        Context context = ContextHolder.getContext();
        
        Directory<Path, X509CertificateObject> directory =
            context == null ? null : context.getX509CertificateDirectory();
        
        return getInstance(obj,directory);
    }

    /**
     * @param obj The ASN.1 object to decode.
     * @param directory The directory used to resolve path references.
     * @return An instance of CommonPublicKeyAttributes.
     */
    public static X509CertificateAttributes getInstance (Object obj,
            Directory<Path, X509CertificateObject> directory)
    {
        if (obj instanceof X509CertificateAttributes)
            return (X509CertificateAttributes)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            X509CertificateAttributes ret = new X509CertificateAttributes();
            
            ret.setValue(X509CertificateObjectFactory.getInstance(objs.nextElement(), directory));
            
            if (!objs.hasMoreElements()) return ret;
            
            Object o = objs.nextElement();
            
            if (o instanceof ASN1Sequence) {
                ret.setSubject(X509Name.getInstance(o));
            
                if (!objs.hasMoreElements()) return ret;
                o = objs.nextElement();
            }
                  
            if (o instanceof ASN1TaggedObject) {
                
                ASN1TaggedObject to = (ASN1TaggedObject)o;
                
                if (to.getTagNo() != 0)
                    throw new IllegalArgumentException("Invalid member tag ["+to.getTagNo()+"] in member of X509CertificateAttributes ASN.1 SEQUENCE.");
                
                
                ret.setIssuer(X509Name.getInstance(to.getObject()));
            
                if (!objs.hasMoreElements()) return ret;
                o = objs.nextElement();
            }
            
            if (o instanceof DERInteger) {
                ret.setSerialNumber(DERInteger.getInstance(o).getValue());
                return ret;
            }
            
            throw new IllegalArgumentException("Invalid member ["+o+"] in X509CertificateAttributes ASN.1 SEQUENCE.");
        }
        
        throw new IllegalArgumentException("X509CertificateAttributes must be encoded as an ASN.1 SEQUENCE.");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (this.value != null)
            v.add(this.value);
        
        if (this.subject != null)
            v.add(this.subject);
        
       if (this.issuer != null)
            v.add(new DERTaggedObject(0,this.issuer));

       if (this.serialNumber != null)
           v.add(new DERInteger(this.serialNumber));

        return new DERSequence(v);
    }

    /**
     * @return the value
     */
    public X509CertificateObject getValue() {
        return this.value;
    }

    /**
     * @param value the value to set
     */
    public void setValue(X509CertificateObject value) {
        this.value = value;
    }

    /**
     * @return the subject
     */
    public X509Name getSubject() {
        return this.subject;
    }

    /**
     * @param subject the subject to set
     */
    public void setSubject(X509Name subject) {
        this.subject = subject;
    }

    /**
     * @return the issuer
     */
    public X509Name getIssuer() {
        return this.issuer;
    }

    /**
     * @param issuer the issuer to set
     */
    public void setIssuer(X509Name issuer) {
        this.issuer = issuer;
    }

    /**
     * @return the serialNumber
     */
    public BigInteger getSerialNumber() {
        return this.serialNumber;
    }

    /**
     * @param serialNumber the serialNumber to set
     */
    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.attr.SpecificCertificateAttributes#getCertificateObject()
     */
    @Override
    public CertificateObject getCertificateObject() {
        
        return this.value;
    }


}
