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
 * TokenFlags ::= BIT STRING {
 *        readonly       (0),
 *        loginRequired (1),
 *        prnGeneration (2),
 *        eidCompliant (3)
 *        }
 * </PRE>
 * 
 * @author wglas
 */
public class TokenFlags extends DERBitString {

    public static final int        readonly      = (1 << 7); 
    public static final int        loginRequired = (1 << 6);
    public static final int        prnGeneration = (1 << 5);
    public static final int        eidCompliant  = (1 << 4);
    
    /**
     * Default constructor initializing to an empty bit mask.
     */
    public TokenFlags() {
        super((byte)0,0);
    }

    /**
     * @param data A bit combination of the static masks.
     */
    public TokenFlags(int data) {
        super((byte)data,0);
    }
    
    /**
     * @param data
     * @param padBits
     */
    protected TokenFlags(DERBitString bs) {
        super(bs.getBytes(),bs.getPadBits());
    }

    /**
     * @param obj
     */
    public TokenFlags(DEREncodable obj) {
        super(obj);
    }

    /**
     * @param obj An ASN1 object.
     * @return An instance of Operations.
     */
    public static TokenFlags getInstance(Object obj)
    {
        if (obj instanceof TokenFlags) {
            return (TokenFlags) obj;
        }
        
        DERBitString bs = DERBitString.getInstance(obj);
        
        if (bs.getBytes() == null || bs.getBytes().length < 1)
            throw new IllegalArgumentException("TokenFlags BIT STRING must conatin at least 8 bits.");
            
        return new TokenFlags(bs);
    }

    public boolean isReadonly()
    {
        return (this.intValue() & readonly) != 0;
    }
    
    public boolean isLoginRequired()
    {
        return (this.intValue() & loginRequired) != 0;
    }
    
    public boolean isPrnGeneration()
    {
        return (this.intValue() & prnGeneration) != 0;
    }
    
    public boolean isEidCompliant()
    {
        return (this.intValue() & eidCompliant) != 0;
    }
    
    private void setBit(int mask, boolean b)
    {
        if (b)
            this.getBytes()[0] |= mask;
        else
            this.getBytes()[0] &= ~mask;
    }
    
    public void setReadonly(boolean b)
    {
        this.setBit(readonly,b);
    }
    
    public void setLoginRequired(boolean b)
    {
        this.setBit(loginRequired,b);
    }
    
    public void setPrnGeneration(boolean b)
    {
        this.setBit(prnGeneration,b);
    }
    
    public void setEidCompliant(boolean b)
    {
        this.setBit(eidCompliant,b);
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
        
        if (this.isReadonly())
            appendBit(sb,"readonly");
        
        if (this.isLoginRequired())
            appendBit(sb,"loginRequired");
        
        if (this.isPrnGeneration())
            appendBit(sb,"prnGeneration");
        
        if (this.isEidCompliant())
            appendBit(sb,"eidCompliant");
       
        sb.append(')');
        
       return sb.toString();
    }
}
