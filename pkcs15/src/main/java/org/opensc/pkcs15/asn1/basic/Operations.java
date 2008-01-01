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

package org.opensc.pkcs15.asn1.basic;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREncodable;

/**
 * <PRE>
 * Operations ::= BIT STRING {
 *    compute-checksum (0), -- H/W computation of checksum
 *    compute-signature (1), -- H/W computation of signature
 *    verify-checksum   (2), -- H/W verification of checksum
 *    verify-signature  (3), -- H/W verification of signature
 *    encipher          (4), -- H/W encryption of data
 *    decipher          (5), -- H/W decryption of data
 *    hash              (6), -- H/W hashing
 *    generate-key      (7) -- H/W key generation
 *  }
 * </PRE>
 * 
 * @author wglas
 */
public class Operations extends DERBitString {

    public static final int        computeChecksum  = (1 << 7); 
    public static final int        computeSignature = (1 << 6);
    public static final int        verifyChecksum   = (1 << 5);
    public static final int        verifySignature  = (1 << 4);
    public static final int        encipher         = (1 << 3);
    public static final int        decipher         = (1 << 2);
    public static final int        hash             = (1 << 1);
    public static final int        generateKey      = (1 << 0);

    /**
     * Default constructor initializing to an empty bit mask.
     */
    public Operations() {
        super((byte)0,0);
    }

    /**
     * @param data A bit combination of the static masks.
     */
    public Operations(int data) {
        super((byte)data,0);
    }
    
    /**
     * @param data
     * @param padBits
     */
    protected Operations(DERBitString bs) {
        super(bs.getBytes(),bs.getPadBits());
    }

    /**
     * @param obj
     */
    public Operations(DEREncodable obj) {
        super(obj);
    }

    /**
     * @param obj An ASN1 object.
     * @return An instance of Operations.
     */
    public static Operations getInstance(Object obj)
    {
        if (obj instanceof Operations) {
            return (Operations) obj;
        }
        
        DERBitString bs = DERBitString.getInstance(obj);
        
        if (bs.getBytes() == null || bs.getBytes().length < 1)
            throw new IllegalArgumentException("Operations BIT STRING must conatin at least 8 bits.");
            
        return new Operations(bs);
    }

    public boolean isComputeChecksum()
    {
        return (this.intValue() & computeChecksum) != 0;
    }
    
    public boolean isComputeSignature()
    {
        return (this.intValue() & computeSignature) != 0;
    }
    
    public boolean isVerfiyChecksum()
    {
        return (this.intValue() & verifyChecksum) != 0;
    }
    
    public boolean isVerfiySignature()
    {
        return (this.intValue() & verifySignature) != 0;
    }
    
    public boolean isEncipher()
    {
        return (this.intValue() & encipher) != 0;
    }
    
    public boolean isDecipher()
    {
        return (this.intValue() & decipher) != 0;
    }
    
    public boolean isHash()
    {
        return (this.intValue() & hash) != 0;
    }
    
    public boolean isGenerateKey()
    {
        return (this.intValue() & generateKey) != 0;
    }
    
    private void setBit(int mask, boolean b)
    {
        if (b)
            this.getBytes()[0] |= mask;
        else
            this.getBytes()[0] &= ~mask;
    }
    
    public void setComputeChecksum(boolean b)
    {
        this.setBit(computeChecksum,b);
    }
    
    public void setComputeSignature(boolean b)
    {
        this.setBit(computeSignature,b);
    }
    
    public void setVerfiyChecksum(boolean b)
    {
        this.setBit(verifyChecksum,b);
    }
    
    public void setVerfiySignature(boolean b)
    {
        this.setBit(verifySignature,b);
    }
    
    public void setEncipher(boolean b)
    {
        this.setBit(encipher,b);
    }
    
    public void setDecipher(boolean b)
    {
        this.setBit(decipher,b);
    }
    
    public void setHash(boolean b)
    {
        this.setBit(hash,b);
    }
    
    public void setGenerateKey(boolean b)
    {
        this.setBit(generateKey,b);
    }
    
    private static void appendBit(StringBuffer sb, String s)
    {
        if (sb.length() > 1)
            sb.append('|');
        sb.append(s);
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.DERBitString#toString()
     */
    public String toString()
    {
        StringBuffer sb = new StringBuffer();
        
        sb.append('(');
        
        if (this.isComputeChecksum())
            appendBit(sb,"computeChecksum");
        
        if (this.isComputeSignature())
            appendBit(sb,"computeSignature");
        
        if (this.isVerfiyChecksum())
            appendBit(sb,"verifyChecksum");
        
        if (this.isVerfiySignature())
            appendBit(sb,"verifySignature");
        
        if (this.isEncipher())
            appendBit(sb,"encipher");
       
        if (this.isDecipher())
            appendBit(sb,"decipher");
       
        if (this.isHash())
            appendBit(sb,"hash");
       
        if (this.isGenerateKey())
            appendBit(sb,"generateKey");
       
        sb.append(')');
        
       return sb.toString();
    }
}
