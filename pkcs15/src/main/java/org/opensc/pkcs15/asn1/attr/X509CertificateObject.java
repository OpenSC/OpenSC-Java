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

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.X509Name;

/**
 * This interface is implemented by X509Certificate instances
 * and proxies. 
 * 
 * @author wglas
 */
public interface X509CertificateObject extends CertificateObject {

    public X509Certificate getX509Certificate() throws CertificateParsingException;
    
    public TBSCertificateStructure getTBSCertificate();

    public int getVersion();

    public DERInteger getSerialNumber();

    public X509Name getIssuer();

    public Time getStartDate();

    public Time getEndDate();

    public X509Name getSubject();

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo();

    public AlgorithmIdentifier getSignatureAlgorithm();

    public DERBitString getSignature();
}
