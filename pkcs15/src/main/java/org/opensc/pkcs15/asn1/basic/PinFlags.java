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
 * PinFlags ::= BIT STRING {
 *         case-sensitive             (0),
 *         local                      (1),
 *         change-disabled            (2),
 *         unblock-disabled           (3),
 *         initialized                (4),
 *         needs-padding              (5),
 *         unblockingPin              (6),
 *         soPin                      (7),
 *         disable-allowed            (8),
 *         integrity-protected        (9),
 *         confidentiality-protected  (10),
 *         exchangeRefData            (11)
 *         } (CONSTRAINED BY { -- 'unblockingPin' and 'soPIN' cannot both be set -- })
 * </PRE>
 * 
 * @author wglas
 */
public class PinFlags extends DERBitString {

    public static final int        caseSensitive            = (1 << 7); 
    public static final int        local                    = (1 << 6);
    public static final int        changeDisabled           = (1 << 5);
    public static final int        unblockDisabled          = (1 << 4);
    public static final int        initialized              = (1 << 3);
    public static final int        needsPadding             = (1 << 2);
    public static final int        unblockingPin            = (1 << 1);
    public static final int        soPin                    = (1 << 0);
    public static final int        disableAllowed           = (1 << 15);
    public static final int        integrityProtected       = (1 << 14);
    public static final int        confidentialityProtected = (1 << 13);
    public static final int        exchangeRefData          = (1 << 12);

    /**
     * Default constructor initializing to an empty bit mask.
     */
    public PinFlags() {
        super(new byte[]{0,0},0);
    }

    /**
     * @param data A bit combination of the static masks.
     */
    public PinFlags(int data) {
        super(new byte[]{(byte)data,(byte)(data>>8)},0);
    }
    
    /**
     * @param data
     * @param padBits
     */
    protected PinFlags(DERBitString bs) {
        super(bs.getBytes(),bs.getPadBits());
    }

    /**
     * @param obj
     */
    public PinFlags(DEREncodable obj) {
        super(obj);
    }

    /**
     * @param obj An ASN1 object.
     * @return An instance of Operations.
     */
    public static PinFlags getInstance(Object obj)
    {
        if (obj instanceof PinFlags) {
            return (PinFlags) obj;
        }
        
        DERBitString bs = DERBitString.getInstance(obj);
        
        if (bs.getBytes() == null || bs.getBytes().length < 2)
            throw new IllegalArgumentException("PinFlags BIT STRING must conatin at least 12 bits.");
            
        return new PinFlags(bs);
    }

    public boolean isCaseSensitive()
    {
        return (this.intValue() & caseSensitive) != 0;
    }
    
    public boolean isLocal()
    {
        return (this.intValue() & local) != 0;
    }
    
    public boolean isChangeDisabled()
    {
        return (this.intValue() & changeDisabled) != 0;
    }
    
    public boolean isUnblockDisabled()
    {
        return (this.intValue() & unblockDisabled) != 0;
    }
    
    public boolean isInitialized()
    {
        return (this.intValue() & initialized) != 0;
    }
    
    public boolean isNeedsPadding()
    {
        return (this.intValue() & needsPadding) != 0;
    }
    
    public boolean isUnblockingPin()
    {
        return (this.intValue() & unblockingPin) != 0;
    }
    
    public boolean isSoPin()
    {
        return (this.intValue() & soPin) != 0;
    }
    
    public boolean isDisableAllowed()
    {
        return (this.intValue() & disableAllowed) != 0;
    }
    
    public boolean isIntegrityProtected()
    {
        return (this.intValue() & integrityProtected) != 0;
    }
    
    public boolean isConfidentialityProtected()
    {
        return (this.intValue() & confidentialityProtected) != 0;
    }
    
    public boolean isExchangeRefData()
    {
        return (this.intValue() & exchangeRefData) != 0;
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
    
    public void setCaseSensitive(boolean b)
    {
        this.setBit(caseSensitive,b);
    }
    
    public void setLocal(boolean b)
    {
        this.setBit(local,b);
    }
    
    public void setChangeDisabled(boolean b)
    {
        this.setBit(changeDisabled,b);
    }
    
    public void setUnblockDisabled(boolean b)
    {
        this.setBit(unblockDisabled,b);
    }
    
    public void setInitialized(boolean b)
    {
        this.setBit(initialized,b);
    }
    
    public void setNeedsPadding(boolean b)
    {
        this.setBit(needsPadding,b);
    }
    
    public void setUnblockingPin(boolean b)
    {
        this.setBit(unblockingPin,b);
    }
    
    public void setSoPin(boolean b)
    {
        this.setBit(soPin,b);
    }
    
    public void setDisableAllowed(boolean b)
    {
        this.setBit(disableAllowed,b);
    }
    
    public void setIntegrityProtected(boolean b)
    {
        this.setBit(integrityProtected,b);
    }
    
    public void setConfidentialityProtected(boolean b)
    {
        this.setBit(confidentialityProtected,b);
    }
    
    public void setExchangeRefData(boolean b)
    {
        this.setBit(exchangeRefData,b);
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
        
        if (this.isCaseSensitive())
            appendBit(sb,"caseSensitive");
        
        if (this.isLocal())
            appendBit(sb,"local");
        
        if (this.isChangeDisabled())
            appendBit(sb,"changeDisabled");
        
        if (this.isUnblockDisabled())
            appendBit(sb,"unblockDisabled");
        
        if (this.isInitialized())
            appendBit(sb,"initialized");
       
        if (this.isNeedsPadding())
            appendBit(sb,"needsPadding");
       
        if (this.isUnblockingPin())
            appendBit(sb,"unblockingPin");
       
        if (this.isSoPin())
            appendBit(sb,"soPin");
       
        if (this.isDisableAllowed())
            appendBit(sb,"disableAllowed");
       
        if (this.isIntegrityProtected())
            appendBit(sb,"integrityProtected");
       
        if (this.isConfidentialityProtected())
            appendBit(sb,"confidentialityProtected");
       
        if (this.isExchangeRefData())
            appendBit(sb,"exchangeRefData");
       
        sb.append(')');
        
       return sb.toString();
    }
}
