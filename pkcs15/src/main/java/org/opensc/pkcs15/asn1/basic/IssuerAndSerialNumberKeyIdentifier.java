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

import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;

/**
 * A KeyIdentifier with an RFC 2630 (CMS) IssuerAndSerialNumber as value.
 * 
 * @author wglas
 */
public class IssuerAndSerialNumberKeyIdentifier extends KeyIdentifier {

    private IssuerAndSerialNumber identifier;
    
    protected IssuerAndSerialNumberKeyIdentifier(IssuerAndSerialNumber identifier) {
        super(issuerAndSerialNumber);
        this.identifier = identifier;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.KeyIdentifier#getValue()
     */
    @Override
    public DEREncodable getValue() {
        
        return this.identifier;
    }

    /**
     * @return the identifier
     */
    public IssuerAndSerialNumber getIdentifier() {
        return this.identifier;
    }

    /**
     * @param identifier the identifier to set
     */
    public void setIdentifier(IssuerAndSerialNumber identifier) {
        this.identifier = identifier;
    }

}
