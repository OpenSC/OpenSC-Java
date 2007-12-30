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

package org.opensc.pkcs15.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * 
 * <PRE> 
 * RSAPrivateKeyObjectImpl ::= SEQUENCE {
 *         modulus            [0] INTEGER OPTIONAL, -- n
 *         publicExponent            [1] INTEGER OPTIONAL, -- e
 *         privateExponent           [2] INTEGER OPTIONAL, -- d
 *         prime1                    [3] INTEGER OPTIONAL, -- p
 *         prime2                    [4] INTEGER OPTIONAL, -- q
 *         exponent1                 [5] INTEGER OPTIONAL, -- d mod (p-1)
 *         exponent2                 [6] INTEGER OPTIONAL, -- d mod (q-1)
 *         coefficient               [7] INTEGER OPTIONAL -- inv(q) mod p
 *         } (CONSTRAINED BY {-- must be possible to reconstruct modulus and privateExponent
 *         -- from selected fields --})
 * </PRE>
 * 
 * @author wglas
 */
public class RSAPrivateKeyObjectImpl implements RSAPrivateKeyObject {

    private static final long serialVersionUID = 5880835995320789138L;
    
    private BigInteger crtCoefficient;
    private BigInteger primeExponentP;
    private BigInteger primeExponentQ;
    private BigInteger primeP;
    private BigInteger primeQ;
    private BigInteger publicExponent;
    private BigInteger privateExponent;
    private BigInteger modulus;

    /**
     * Default constructor.
     */
    public RSAPrivateKeyObjectImpl()
    {}
    
    /**
     * @param obj The ASN.1 object to decode.
     * @return An instance of RSAPrivateKeyObjectImpl.
     */
    public static RSAPrivateKeyObjectImpl getInstance(Object obj)
    {
        if (obj instanceof RSAPrivateKeyObjectImpl) {
            return (RSAPrivateKeyObjectImpl) obj;    
        }
        
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            RSAPrivateKeyObjectImpl ret = new RSAPrivateKeyObjectImpl();
            
            Enumeration<Object> objs = seq.getObjects();
            
            while (objs.hasMoreElements()) {
                
                Object o = objs.nextElement();
                
                if (!(o instanceof ASN1TaggedObject))
                    throw new IllegalArgumentException("RSAPrivateKeyObjectImpl member must be encoded as an ASN.1 tagged objects.");
                
                ASN1TaggedObject to = (ASN1TaggedObject)o;
                
                DERInteger v = DERInteger.getInstance(to.getObject());
                
                switch (to.getTagNo())
                {
                case 0:
                    ret.setModulus(v.getValue());
                    break;
                    
                case 1:
                    ret.setPublicExponent(v.getValue());
                    break;

                case 2:
                    ret.setPrivateExponent(v.getValue());
                    break;
 
                case 3:
                    ret.setPrimeP(v.getValue());
                    break;
                    
                case 4:
                    ret.setPrimeQ(v.getValue());
                    break;
                    
                case 5:
                    ret.setPrimeExponentP(v.getValue());
                    break;
                    
                case 6:
                    ret.setPrimeExponentQ(v.getValue());
                    break;
 
                case 7:
                    ret.setCrtCoefficient(v.getValue());
                    break;
                    
                default:
                    throw new IllegalArgumentException("Invalid RSAPrivateKeyObjectImpl member tag ["+to.getTagNo()+"].");
                }
            }
            return ret;
        }
        
        throw new IllegalArgumentException("RSAPrivateKeyObject must be encoded as an ASN.1 SEQUENCE.");
    }
    
    @Override
    public BigInteger getCrtCoefficient() {
        
        return this.crtCoefficient;
    }

    @Override
    public BigInteger getPrimeExponentP() {
        
        return this.primeExponentP;
    }

    @Override
    public BigInteger getPrimeExponentQ() {
        
        return this.primeExponentQ;
    }

    @Override
    public BigInteger getPrimeP() {
      
        return this.primeP;
    }

    @Override
    public BigInteger getPrimeQ() {
        
        return this.primeQ;
    }

    @Override
    public BigInteger getPublicExponent() {
        
        return this.publicExponent;
    }

    @Override
    public BigInteger getPrivateExponent() {
        
        return this.privateExponent;
    }

    @Override
    public String getAlgorithm() {
        
        return "RSA";
    }

    @Override
    public String getFormat() {
        
        return "PKCS#15";
    }

    @Override
    public BigInteger getModulus() {
        
        return this.modulus;
    }

    /**
     * @param crtCoefficient the crtCoefficient to set
     */
    public void setCrtCoefficient(BigInteger crtCoefficient) {
        this.crtCoefficient = crtCoefficient;
    }

    /**
     * @param primeExponentP the primeExponentP to set
     */
    public void setPrimeExponentP(BigInteger primeExponentP) {
        this.primeExponentP = primeExponentP;
    }

    /**
     * @param primeExponentQ the primeExponentQ to set
     */
    public void setPrimeExponentQ(BigInteger primeExponentQ) {
        this.primeExponentQ = primeExponentQ;
    }

    /**
     * @param primeP the primeP to set
     */
    public void setPrimeP(BigInteger primeP) {
        this.primeP = primeP;
    }

    /**
     * @param primeQ the primeQ to set
     */
    public void setPrimeQ(BigInteger primeQ) {
        this.primeQ = primeQ;
    }

    /**
     * @param publicExponent the publicExponent to set
     */
    public void setPublicExponent(BigInteger publicExponent) {
        this.publicExponent = publicExponent;
    }

    /**
     * @param privateExponent the privateExponent to set
     */
    public void setPrivateExponent(BigInteger privateExponent) {
        this.privateExponent = privateExponent;
    }

    /**
     * @param modulus the modulus to set
     */
    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    @Override
    public byte[] getEncoded() {
        
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ASN1OutputStream aos = new ASN1OutputStream(bos);
            aos.writeObject(this.getDERObject());
            return bos.toByteArray();
        } catch (IOException e) {
            throw new SecurityException("Cannot encode PKCS#15 RSAPrivateKeyObjectImpl.",e);
        }
    }

    @Override
    public DERObject getDERObject() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERTaggedObject(0,new DERInteger(this.modulus)));
        v.add(new DERTaggedObject(1,new DERInteger(this.publicExponent)));
        v.add(new DERTaggedObject(2,new DERInteger(this.privateExponent)));
        v.add(new DERTaggedObject(3,new DERInteger(this.primeP)));
        v.add(new DERTaggedObject(4,new DERInteger(this.primeQ)));
        v.add(new DERTaggedObject(5,new DERInteger(this.primeExponentP)));
        v.add(new DERTaggedObject(6,new DERInteger(this.primeExponentQ)));
        v.add(new DERTaggedObject(7,new DERInteger(this.crtCoefficient)));

        return new DERSequence(v);
    }

}
