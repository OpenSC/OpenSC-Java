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
 * Created: 01.01.2008
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1.attr;

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Name;

/**
 * This is an adapter for mapping bouncycastle's X509CertificateStructure to
 * out interface X509CertificateObject.
 * 
 * @author wglas
 */
public class X509CertificateObjectImpl implements X509CertificateObject {
    
    private final X509CertificateStructure delegate;
    
    /**
     * @param delegate The bouncycastle ASN.1 object to wrap.
     */
    X509CertificateObjectImpl(X509CertificateStructure delegate)
    {
        this.delegate = delegate;
    }
    
    /**
     * @param obj The ASN.1 object to be parsed.
     * @return An X509CertificateObject instance.
     */
    public static X509CertificateObject getInstance(Object obj)
    {
        if (obj instanceof X509CertificateObject)
            return (X509CertificateObject) obj;
        
        return new X509CertificateObjectImpl(X509CertificateStructure.getInstance(obj));        
    }
    
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.attr.X509CertificateObject#getEndDate()
     */
    @Override
    public Time getEndDate() {
        return this.delegate.getEndDate();
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.attr.X509CertificateObject#getIssuer()
     */
    @Override
    public X509Name getIssuer() {
        return this.delegate.getIssuer();
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.attr.X509CertificateObject#getSerialNumber()
     */
    @Override
    public DERInteger getSerialNumber() {
        return this.delegate.getSerialNumber();
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.attr.X509CertificateObject#getSignature()
     */
    @Override
    public DERBitString getSignature() {
        return this.delegate.getSignature();
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.attr.X509CertificateObject#getSignatureAlgorithm()
     */
    @Override
    public AlgorithmIdentifier getSignatureAlgorithm() {
        return this.delegate.getSignatureAlgorithm();
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.attr.X509CertificateObject#getStartDate()
     */
    @Override
    public Time getStartDate() {
        return this.delegate.getStartDate();
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.attr.X509CertificateObject#getSubject()
     */
    @Override
    public X509Name getSubject() {
        return this.delegate.getSubject();
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.attr.X509CertificateObject#getSubjectPublicKeyInfo()
     */
    @Override
    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return this.delegate.getSubjectPublicKeyInfo();
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.attr.X509CertificateObject#getTBSCertificate()
     */
    @Override
    public TBSCertificateStructure getTBSCertificate() {
        return this.delegate.getTBSCertificate();
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.attr.X509CertificateObject#getVersion()
     */
    @Override
    public int getVersion() {
        return this.delegate.getVersion();
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.DEREncodable#getDERObject()
     */
    @Override
    public DERObject getDERObject() {
        return this.delegate.getDERObject();
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.attr.X509CertificateObject#getX509Certificate()
     */
    @Override
    public X509Certificate getX509Certificate() throws CertificateParsingException {
        return new org.bouncycastle.jce.provider.X509CertificateObject(this.delegate);
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.attr.CertificateObject#getCertificate()
     */
    @Override
    public Certificate getCertificate() throws CertificateParsingException {
        
        return this.getX509Certificate();
    }

}
