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
 * CommonObjectFlags ::= BIT STRING {
 *      private        (0),
 *      modifiable     (1)
 *      }
 * </PRE>
 * 
 * @author wglas
 */
public class CommonObjectFlags extends DERBitString {

    public static final int        privateFlag = (1 << 7); 
    public static final int        modifiable  = (1 << 6);

    /**
     * Default constructor initializing to an empty bit mask.
     */
    public CommonObjectFlags() {
        super((byte)0,0);
    }

    /**
     * @param data A bit combination of the static masks.
     */
    public CommonObjectFlags(int data) {
        super((byte)data,0);
    }
    
    /**
     * @param data
     * @param padBits
     */
    protected CommonObjectFlags(DERBitString bs) {
        super(bs.getBytes(),bs.getPadBits());
    }

    /**
     * @param obj
     */
    public CommonObjectFlags(DEREncodable obj) {
        super(obj);
    }

    /**
     * @param obj An ASN1 object.
     * @return An instance of CommonObjectFlags.
     */
    public static CommonObjectFlags getInstance(Object obj)
    {
        if (obj instanceof CommonObjectFlags) {
            return (CommonObjectFlags) obj;
        }
        
        DERBitString bs = DERBitString.getInstance(obj);
        
        if (bs.getBytes() == null || bs.getBytes().length < 1)
            throw new IllegalArgumentException("CommonObjectFlags BIT STRING must conatin at least 2 bits.");
            
        return new CommonObjectFlags(bs);
    }

    public boolean isPrivate()
    {
        return (this.intValue() & privateFlag) != 0;
    }
    
    public boolean isModifiable()
    {
        return (this.intValue() & modifiable) != 0;
    }
    
    private void setBit(int mask, boolean b)
    {
        if (b)
            this.getBytes()[0] |= mask;
        else
            this.getBytes()[0] &= ~mask;
    }
    
    public void setPrivate(boolean b)
    {
        this.setBit(privateFlag,b);
    }
    
    public void setModifiable(boolean b)
    {
        this.setBit(modifiable,b);
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
        
        if (this.isPrivate())
            appendBit(sb,"private");
        
        if (this.isModifiable())
            appendBit(sb,"modifiable");
       
        sb.append(')');
        
       return sb.toString();
    }
}
