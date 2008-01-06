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
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.opensc.pkcs15.asn1.Context;
import org.opensc.pkcs15.asn1.ContextHolder;
import org.opensc.pkcs15.asn1.basic.KeyInfo;
import org.opensc.pkcs15.asn1.basic.Operations;
import org.opensc.pkcs15.asn1.basic.RSAKeyInfo;
import org.opensc.pkcs15.asn1.proxy.Directory;
import org.opensc.pkcs15.asn1.ref.Path;

/**
 * <PRE> 
 * PublicRSAKeyAttributes ::= SEQUENCE {
 *        value                   ObjectValue {RSAPublicKeyChoice},
 *        modulusLength           INTEGER, -- modulus length in bits, e.g. 1024
 *        keyInfo                 KeyInfo {NULL, PublicKeyOperations} OPTIONAL,
 *        ... -- For future extensions
 *        }
 * </PRE>
 * 
 * @author wglas
 */
public class PublicRSAKeyAttributes extends ASN1Encodable implements SpecificPublicKeyAttributes {

    private RSAPublicKeyObject value;
    private BigInteger modulusLength;
    private RSAKeyInfo keyInfo;
    
    /**
     * Default constructor.
     */
    public PublicRSAKeyAttributes() {
        super();
    }

    /**
     * This method implements the static getInstance factory pattern by
     * using the thread-local context stored in {@link ContextHolder}. 
     * 
     * @param obj ASN.1 object to be decoded.
     * @return A KeyInfo object suitable for RSA Private keys.
     */
    static public PublicRSAKeyAttributes getInstance(Object obj)
    {
        Context context = ContextHolder.getContext();
        
        Directory<DERInteger,RSAKeyInfo> infoDirectory =
            context == null ? null : context.getRSAKeyInfoDirectory();
        
        Directory<Path, RSAPublicKeyObject> keyKirectory =
            context == null ? null : context.getRSAPublicKeyDirectory();
        
        return getInstance(obj,keyKirectory,infoDirectory);
    }

    /**
     * @param obj The ASN.1 object to decode.
     * @param keyKirectory The directory used to resolve referenced private key objects.
     * @param infoDirectory The directory used to resolve KeyInfos.
     * @return An instance of CommonPrivateKeyAttributes.
     */
    public static PublicRSAKeyAttributes getInstance (Object obj,
            Directory<Path, RSAPublicKeyObject> keyKirectory,
            Directory<DERInteger, RSAKeyInfo> infoDirectory)
    {
        if (obj instanceof PublicRSAKeyAttributes)
            return (PublicRSAKeyAttributes)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            PublicRSAKeyAttributes ret = new PublicRSAKeyAttributes();
         
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing value member in PrivateRSAKeyAttributes SEQUENCE.");

            ret.setValue(RSAPublicKeyObjectFactory.getInstance(objs.nextElement(), keyKirectory));
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing modulusLength member in PrivateRSAKeyAttributes SEQUENCE.");

            ret.setModulusLength(DERInteger.getInstance(objs.nextElement()).getValue());
            
            if (objs.hasMoreElements()) {
                
                ret.setKeyInfo(RSAKeyInfoFactory.getInstance(objs.nextElement(),infoDirectory));
            }
               
            return ret;
        }
        
        throw new IllegalArgumentException("PrivateRSAKeyAttributes must be encoded as an ASN.1 SEQUENCE.");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (this.value != null)
            v.add(this.value);
        
        if (this.modulusLength != null)
            v.add(new DERInteger(this.modulusLength));
        
        if (this.keyInfo != null)
            v.add(this.keyInfo);

        return new DERSequence(v);
    }

    /**
     * @return the value
     */
    public RSAPublicKeyObject getValue() {
        return this.value;
    }

    /**
     * @param value the value to set
     */
    public void setValue(RSAPublicKeyObject value) {
        this.value = value;
    }

    /**
     * @return the modulusLength
     */
    public BigInteger getModulusLength() {
        return this.modulusLength;
    }

    /**
     * @param modulusLength the modulusLength to set
     */
    public void setModulusLength(BigInteger modulusLength) {
        this.modulusLength = modulusLength;
    }

    /**
     * @return the keyInfo
     */
    public RSAKeyInfo getKeyInfo() {
        return this.keyInfo;
    }

    /**
     * @param keyInfo the keyInfo to set
     */
    public void setKeyInfo(RSAKeyInfo keyInfo) {
        this.keyInfo = keyInfo;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.attr.SpecificPublicKeyAttributes#getGenericKeyInfo()
     */
    @Override
    public KeyInfo<? extends DEREncodable, Operations> getGenericKeyInfo() {
        return this.keyInfo;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.attr.SpecificPublicKeyAttributes#getPublicKeyObject()
     */
    @Override
    public PublicKeyObject getPublicKeyObject() {
        return this.value;
    }

}
