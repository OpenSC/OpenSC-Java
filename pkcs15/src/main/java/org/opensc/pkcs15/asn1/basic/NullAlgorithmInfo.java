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
 * Created: 08.01.2008
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1.basic;

import org.bouncycastle.asn1.DEREncodable;

/**
 * An AlgorithmInfo with a NULL <code>parameters</code> member. 
 * 
 * @author wglas
 */
public class NullAlgorithmInfo extends AlgorithmInfo {

    private NullKeyInfoImpl nullKeyInfo;
    
    protected NullAlgorithmInfo(int reference, int algorithm, NullKeyInfoImpl nullKeyInfo) {
        super(reference, algorithm);
        this.nullKeyInfo = nullKeyInfo;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.basic.AlgorithmInfo#getKeyInfo()
     */
    @Override
    public KeyInfoImpl<? extends DEREncodable, Operations> getKeyInfo() {
        
        return this.nullKeyInfo;
    }

    /**
     * @return the nullKeyInfo
     */
    public NullKeyInfoImpl getNullKeyInfo() {
        return this.nullKeyInfo;
    }

    /**
     * @param nullKeyInfo the nullKeyInfo to set
     */
    public void setNullKeyInfo(NullKeyInfoImpl nullKeyInfo) {
        this.nullKeyInfo = nullKeyInfo;
    }

}
