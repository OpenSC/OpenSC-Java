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
 * Created: 01.01.2008
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1.basic;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERObject;

/**
 * PinType ::= ENUMERATED {bcd, ascii-numeric, utf8, ..., half-nibble-bcd, iso9564-1}
 * 
 * @author wglas
 */
public class PinType extends ASN1Encodable {

    public static final int bcd = 0;
    public static final int asciiNumeric = 1;
    public static final int utf8 = 2;
    public static final int halfNibbleBcd = 3;
    public static final int iso9564_1 =4;

    private int value;
    
    public PinType() {
        this.value = bcd;
    }
    
    public PinType(DEREnumerated e) {
        
        if (e.getValue().intValue() < 0 || e.getValue().intValue() > iso9564_1)
            throw new IllegalArgumentException("Invalid PinType enum value ["+e.getValue()+"]");
        
        this.value = e.getValue().intValue();
    }
    
    public static PinType getInstance(Object obj) {
        
        return new PinType(DEREnumerated.getInstance(obj));
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        return new DEREnumerated(this.value);
    }

    /**
     * @return the value
     */
    public int getValue() {
        return this.value;
    }

    /**
     * @param value the value to set
     */
    public void setValue(int value) {
        if (value < 0 || value > iso9564_1)
            throw new IllegalArgumentException("Invalid PinType enum value ["+value+"]");

        this.value = value;
    }
        
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        switch (this.value) {
        
        case bcd:
            return "bcd";
            
        case asciiNumeric:
            return "ascii-numeric";
            
        case utf8:
            return "utf8";
        
        case halfNibbleBcd:
            return "half-nibble-bcd";
            
        case iso9564_1:
            return "iso9564-1";
            
        default:
            return "<invalid PinType "+this.value+">";
        }
    }
}
