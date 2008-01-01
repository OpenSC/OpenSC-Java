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

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEREncodable;

/**
 * A KeyIdentifier with an OCTET STRING as value.
 * 
 * @author wglas
 */
public class OctetStringKeyIdentifier extends KeyIdentifier {
    
    private ASN1OctetString octets;
    
    public OctetStringKeyIdentifier(int id, ASN1OctetString octets) {        
        super(id);
        if (id == issuerAndSerialNumber)
            throw new IllegalArgumentException("issuerAndSerialNumber is incompatible with OctetStringKeyIdentifier.");
        this.octets = octets;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.KeyIdentifier#getValue()
     */
    @Override
    public DEREncodable getValue() {
        
        return this.octets;
    }

    /**
     * @return the octets
     */
    public ASN1OctetString getOctets() {
        return this.octets;
    }

    /**
     * @param octets the octets to set
     */
    public void setOctets(ASN1OctetString octets) {
        this.octets = octets;
    }

}
