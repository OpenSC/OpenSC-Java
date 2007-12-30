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
 * AccessMode ::= BIT STRING {
 *         read     (0),
 *         update (1),
 *         execute (2)
 *         }
 * </PRE>
 * 
 * @author wglas
 */
public class AccessMode extends DERBitString {

    public static final int        read    = (1 << 7); 
    public static final int        update  = (1 << 6);
    public static final int        execute = (1 << 5);

    /**
     * Default constructor initializing to an empty bit mask.
     */
    public AccessMode() {
        super((byte)0,0);
    }

    /**
     * @param data A bit combination of the static masks.
     */
    public AccessMode(int data) {
        super((byte)data,0);
    }
    
    /**
     * @param data
     * @param padBits
     */
    protected AccessMode(DERBitString bs) {
        super(bs.getBytes(),bs.getPadBits());
    }

    /**
     * @param obj
     */
    public AccessMode(DEREncodable obj) {
        super(obj);
    }

    /**
     * @param obj An ASN1 object.
     * @return An instance of AccessMode.
     */
    public static AccessMode getInstance(Object obj)
    {
        if (obj instanceof AccessMode) {
            return (AccessMode) obj;
        }
        
        DERBitString bs = DERBitString.getInstance(obj);
        
        if (bs.getBytes() == null || bs.getBytes().length < 1)
            throw new IllegalArgumentException("AccessMode BIT STRING must conatin at least 3 bits.");
            
        return new AccessMode(bs);
    }

    public boolean isRead()
    {
        return (this.intValue() & read) != 0;
    }
    
    public boolean isUpdate()
    {
        return (this.intValue() & update) != 0;
    }
    
    public boolean isExecute()
    {
        return (this.intValue() & execute) != 0;
    }
    
    private void setBit(int mask, boolean b)
    {
        if (b)
            this.getBytes()[0] |= mask;
        else
            this.getBytes()[0] &= ~mask;
    }
    
    public void setRead(boolean b)
    {
        this.setBit(read,b);
    }
    
    public void setUpdate(boolean b)
    {
        this.setBit(update,b);
    }
    
    public void setExecute(boolean b)
    {
        this.setBit(execute,b);
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
        
        if (this.isRead())
            appendBit(sb,"read");
        
        if (this.isUpdate())
            appendBit(sb,"update");
        
        if (this.isExecute())
            appendBit(sb,"execute");
       
        sb.append(')');
        
       return sb.toString();
    }
}
