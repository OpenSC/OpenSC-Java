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
 * KeyUsageFlags ::= BIT STRING {
 *        encrypt             (0),
 *        decrypt             (1),
 *        sign                (2),
 *        signRecover         (3),
 *        wrap                (4),
 *        unwrap              (5),
 *        verify              (6),
 *        verifyRecover       (7),
 *        derive              (8),
 *        nonRepudiation      (9)
 *        }
 * </PRE>
 * 
 * @author wglas
 */
public class KeyUsageFlags extends DERBitString {

    public static final int        encrypt          = (1 << 7); 
    public static final int        decrypt          = (1 << 6);
    public static final int        sign             = (1 << 5);
    public static final int        signRecover      = (1 << 4);
    public static final int        wrap             = (1 << 3);
    public static final int        unwrap           = (1 << 2);
    public static final int        verify           = (1 << 1);
    public static final int        verifyRecover    = (1 << 0);
    public static final int        derive           = (1 << 15);
    public static final int        nonRepudiation   = (1 << 14);

    /**
     * Default constructor initializing to an empty bit mask.
     */
    public KeyUsageFlags() {
        super((byte)0,0);
    }

    /**
     * @param data A bit combination of the static masks.
     */
    public KeyUsageFlags(int data) {
        super((byte)data,0);
    }
    
    /**
     * @param data
     * @param padBits
     */
    protected KeyUsageFlags(DERBitString bs) {
        super(bs.getBytes(),bs.getPadBits());
    }

    /**
     * @param obj
     */
    public KeyUsageFlags(DEREncodable obj) {
        super(obj);
    }

    /**
     * @param obj An ASN1 object.
     * @return An instance of Operations.
     */
    public static KeyUsageFlags getInstance(Object obj)
    {
        if (obj instanceof KeyUsageFlags) {
            return (KeyUsageFlags) obj;
        }
        
        DERBitString bs = DERBitString.getInstance(obj);
        
        if (bs.getBytes() == null || bs.getBytes().length < 2)
            throw new IllegalArgumentException("KeyUsageFlags BIT STRING must conatin at least 10 bits.");
            
        return new KeyUsageFlags(bs);
    }

    public boolean isEncrypt()
    {
        return (this.intValue() & encrypt) != 0;
    }
    
    public boolean isDecrypt()
    {
        return (this.intValue() & decrypt) != 0;
    }
    
    public boolean isSign()
    {
        return (this.intValue() & sign) != 0;
    }
    
    public boolean isSignRecover()
    {
        return (this.intValue() & signRecover) != 0;
    }
    
    public boolean isWrap()
    {
        return (this.intValue() & wrap) != 0;
    }
    
    public boolean isUnwrap()
    {
        return (this.intValue() & unwrap) != 0;
    }
    
    public boolean isVerify()
    {
        return (this.intValue() & verify) != 0;
    }
    
    public boolean isVerifyRecover()
    {
        return (this.intValue() & verifyRecover) != 0;
    }
    
    public boolean isDerive()
    {
        return (this.intValue() & derive) != 0;
    }
    
    public boolean isNonRepudiation()
    {
        return (this.intValue() & nonRepudiation) != 0;
    }
    
   private void setBit(int mask, boolean b)
   {
       int i =0;
       if (mask > (1 << 7)) {
           
           mask >>= 8;
           i = 1;
       }
       
        if (b)
            this.getBytes()[i] |= mask;
        else
            this.getBytes()[i] &= ~mask;
    }
    
    public void setEncrypt(boolean b)
    {
        this.setBit(encrypt,b);
    }
    
    public void setDecrypt(boolean b)
    {
        this.setBit(decrypt,b);
    }
    
    public void setSign(boolean b)
    {
        this.setBit(sign,b);
    }
    
    public void setSignRecover(boolean b)
    {
        this.setBit(signRecover,b);
    }
    
    public void setWrap(boolean b)
    {
        this.setBit(wrap,b);
    }
    
    public void setUnwrap(boolean b)
    {
        this.setBit(unwrap,b);
    }
    
    public void setVerify(boolean b)
    {
        this.setBit(verify,b);
    }
    
    public void setVerifyRecover(boolean b)
    {
        this.setBit(verifyRecover,b);
    }
    
    public void setDerive(boolean b)
    {
        this.setBit(derive,b);
    }
    
    public void setNonRepudiation(boolean b)
    {
        this.setBit(nonRepudiation,b);
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
        
        if (this.isEncrypt())
            appendBit(sb,"encrypt");
        
        if (this.isDecrypt())
            appendBit(sb,"decrypt");
        
        if (this.isSign())
            appendBit(sb,"sign");
        
        if (this.isSignRecover())
            appendBit(sb,"signRecover");
        
        if (this.isWrap())
            appendBit(sb,"wrap");
       
        if (this.isUnwrap())
            appendBit(sb,"unwrap");
       
        if (this.isVerify())
            appendBit(sb,"verify");
       
        if (this.isVerifyRecover())
            appendBit(sb,"verifyRecover");
       
        if (this.isDerive())
            appendBit(sb,"derive");
       
        if (this.isNonRepudiation())
            appendBit(sb,"nonRepudiation");
       
        sb.append(')');
        
       return sb.toString();
    }
}
