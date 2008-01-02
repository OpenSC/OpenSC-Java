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
 * Created: 31.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1.attr;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.RSAPublicKeyStructure;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * <PRE>
 * RSAPublicKeyChoice ::= CHOICE {
 *       raw     RSAPublicKey -- See PKCS #1,
 *       spki    [1] SubjectPublicKeyInfo, -- See X.509. Must contain a public RSA key
 *       ...
 *       }
 * </PRE>
 * 
 * @author wglas
 */
public class RSAPublicKeyChoice implements RSAPublicKeyObject {
    
    private static final long serialVersionUID = -2447991123936660233L;

    private final RSAPublicKeyStructure raw;
    private final SubjectPublicKeyInfo spki;
    
    public RSAPublicKeyChoice(RSAPublicKeyStructure raw) {
        this.raw = raw;
        this.spki = null;
    }
    
    public RSAPublicKeyChoice(SubjectPublicKeyInfo spki) {
        this.spki = spki;
        
        try
        {
            RSAPublicKeyStructure   pubKey = new RSAPublicKeyStructure((ASN1Sequence)spki.getPublicKey());
            
            this.raw =  new RSAPublicKeyStructure(pubKey.getModulus(),pubKey.getPublicExponent());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid info structure in RSA public key");
        }
    }

    static public RSAPublicKeyChoice getInstance(Object obj) {
        
        if (obj instanceof RSAPublicKeyChoice)
            return (RSAPublicKeyChoice)obj;
        
        if (obj instanceof SubjectPublicKeyInfo)
            return new RSAPublicKeyChoice((SubjectPublicKeyInfo)obj);
        
        if (obj instanceof RSAPublicKeyStructure)
            return new RSAPublicKeyChoice((RSAPublicKeyStructure)obj);
        
        if (obj instanceof ASN1Sequence)
            return new RSAPublicKeyChoice(RSAPublicKeyStructure.getInstance(obj));
        
        if (obj instanceof ASN1TaggedObject) {
         
            ASN1TaggedObject to = (ASN1TaggedObject)obj;
            
            if (to.getTagNo() != 1)
                throw new IllegalArgumentException("Invalid member tag ["+to.getTagNo()+"] in RSAPublicKeyChoice.");
                
            return new RSAPublicKeyChoice(SubjectPublicKeyInfo.getInstance(to.getObject()));
        }
        
        throw new IllegalArgumentException("Invalid RSAPublicKeyChoice.");
    }
    
    /* (non-Javadoc)
     * @see java.security.interfaces.RSAPublicKey#getPublicExponent()
     */
    public BigInteger getPublicExponent() {
        
        return this.raw.getPublicExponent();
    }

    /* (non-Javadoc)
     * @see java.security.Key#getAlgorithm()
     */
    public String getAlgorithm() {
        
        return "RSA";
    }

    /* (non-Javadoc)
     * @see java.security.Key#getFormat()
     */
    public String getFormat() {
        
        return "PKCS#15";
    }

    /* (non-Javadoc)
     * @see java.security.interfaces.RSAKey#getModulus()
     */
    public BigInteger getModulus() {
        
        return this.raw.getModulus();
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.DEREncodable#getDERObject()
     */
    @Override
    public DERObject getDERObject() {
        
        if (this.spki != null)
            return new DERTaggedObject(1,this.spki);
        else
            return this.raw.toASN1Object();
    }

    /* (non-Javadoc)
     * @see java.security.Key#getEncoded()
     */
    public byte[] getEncoded() {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ASN1OutputStream aos = new ASN1OutputStream(bos);
            aos.writeObject(this.getDERObject());
            return bos.toByteArray();
        } catch (IOException e) {
            throw new SecurityException("Cannot encode PKCS#15 RSAPublicKeyChoice.",e);
        }
    }

}
