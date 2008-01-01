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
 * Created: 29.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1.basic;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * @author wglas
 *
 */
public class KeyInfoImpl<ParameterType extends DEREncodable,
                         OperationsType extends DEREncodable> extends ASN1Encodable
implements KeyInfo<ParameterType,OperationsType> {

    private ParameterType parameters;
    private OperationsType supportedOperations;
    
    /**
     * Default constructor.
     */
    public KeyInfoImpl()
    {}
            
    /**
     * @param parameters
     * @param supportedOperations
     */
    public KeyInfoImpl(ParameterType parameters,
            OperationsType supportedOperations) {
        super();
        this.parameters = parameters;
        this.supportedOperations = supportedOperations;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.KeyInfo#getParameters()
     */
    @Override
    public ParameterType getParameters() {
        
        return this.parameters;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.KeyInfo#getSupportedOperations()
     */
    @Override
    public OperationsType getSupportedOperations() {
        
        return this.supportedOperations;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.KeyInfo#setParameters(java.lang.Object)
     */
    @Override
    public void setParameters(ParameterType parameters) {
       
        this.parameters = parameters;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.KeyInfo#setSupportedOperations(java.lang.Object)
     */
    @Override
    public void setSupportedOperations(OperationsType supportedOperations) {
        
        this.supportedOperations = supportedOperations;
    }

    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(this.parameters);
        v.add(this.supportedOperations);

        return new DERSequence(v);
    }

 
}
