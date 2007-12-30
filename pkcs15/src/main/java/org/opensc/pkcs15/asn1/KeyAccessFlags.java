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

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREncodable;

/**
 * <PRE>
 * KeyAccessFlags ::= BIT STRING {
 *        sensitive           (0),
 *        extractable         (1),
 *        alwaysSensitive     (2),
 *        neverExtractable    (3),
 *        local               (4)
 *        }
 * </PRE>
 * 
 * @author wglas
 */
public class KeyAccessFlags extends DERBitString {

    public static final int        sensitive        = (1 << 7); 
    public static final int        extractable      = (1 << 6);
    public static final int        alwaysSensitive  = (1 << 5);
    public static final int        neverExtractable = (1 << 4);
    public static final int        local            = (1 << 3);
 
    /**
     * Default constructor initializing to an empty bit mask.
     */
    public KeyAccessFlags() {
        super((byte)0,0);
    }

    /**
     * @param data A bit combination of the static masks.
     */
    public KeyAccessFlags(int data) {
        super((byte)data,0);
    }
    
    /**
     * @param data
     * @param padBits
     */
    protected KeyAccessFlags(DERBitString bs) {
        super(bs.getBytes(),bs.getPadBits());
    }

    /**
     * @param obj
     */
    public KeyAccessFlags(DEREncodable obj) {
        super(obj);
    }

    /**
     * @param obj An ASN1 object.
     * @return An instance of Operations.
     */
    public static KeyAccessFlags getInstance(Object obj)
    {
        if (obj instanceof KeyAccessFlags) {
            return (KeyAccessFlags) obj;
        }
        
        DERBitString bs = DERBitString.getInstance(obj);
        
        if (bs.getBytes() == null || bs.getBytes().length < 1)
            throw new IllegalArgumentException("Operations BIT STRING must conatin at least 8 bits.");
            
        return new KeyAccessFlags(bs);
    }

    public boolean isSensitive()
    {
        return (this.intValue() & sensitive) != 0;
    }
    
    public boolean isExtractable()
    {
        return (this.intValue() & extractable) != 0;
    }
    
    public boolean isAlwaysSensitive()
    {
        return (this.intValue() & alwaysSensitive) != 0;
    }
    
    public boolean isNeverExtractable()
    {
        return (this.intValue() & neverExtractable) != 0;
    }
    
    public boolean isLocal()
    {
        return (this.intValue() & local) != 0;
    }
 
    private void setBit(int mask, boolean b)
    {
        if (b)
            this.getBytes()[0] |= mask;
        else
            this.getBytes()[0] &= ~mask;
    }
    
    public void setSensitive(boolean b)
    {
        this.setBit(sensitive,b);
    }
    
    public void setExtractable(boolean b)
    {
        this.setBit(extractable,b);
    }
    
    public void setAlwaysSensitive(boolean b)
    {
        this.setBit(alwaysSensitive,b);
    }
    
    public void setNeverExtractable(boolean b)
    {
        this.setBit(neverExtractable,b);
    }
    
    public void setLocal(boolean b)
    {
        this.setBit(local,b);
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
        
        if (this.isSensitive())
            appendBit(sb,"sensitive");
        
        if (this.isExtractable())
            appendBit(sb,"extractable");
        
        if (this.isAlwaysSensitive())
            appendBit(sb,"alwaysSensitive");
        
        if (this.isNeverExtractable())
            appendBit(sb,"neverExtractable");
        
        if (this.isLocal())
            appendBit(sb,"local");
       
        sb.append(')');
        
       return sb.toString();
    }
}
