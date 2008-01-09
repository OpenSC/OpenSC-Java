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
 * Created: 06.01.2008
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1.basic;

import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERObject;

/**
 * The actual implementation of a {@link GeneralizedTimeHolder}.
 * 
 * @author wglas
 */
public class GeneralizedTimeHolderImpl implements GeneralizedTimeHolder {

    private DERGeneralizedTime generalizedTime;
    
    public GeneralizedTimeHolderImpl() {
    }
    
    public GeneralizedTimeHolderImpl(DERGeneralizedTime generalizedTime) {
        this.generalizedTime = generalizedTime;
    }
    
    /**
     * @param obj The ASN.1 object to parse.
     * @return A GeneralizedTimeHoledr instance.
     */
    public static GeneralizedTimeHolder getInstance(Object obj) {
        
        if (obj instanceof GeneralizedTimeHolder)
            return (GeneralizedTimeHolder) obj;
        
        return new GeneralizedTimeHolderImpl(DERGeneralizedTime.getInstance(obj));
    }
    
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.basic.GeneralizedTimeHolder#getGeneralizedTime()
     */
    @Override
    public DERGeneralizedTime getGeneralizedTime() {
        
        return this.generalizedTime;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.basic.GeneralizedTimeHolder#setGeneralizedTime(org.bouncycastle.asn1.DERGeneralizedTime)
     */
    @Override
    public void setGeneralizedTime(DERGeneralizedTime generalizedTime) {
        
        this.generalizedTime = generalizedTime;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.DEREncodable#getDERObject()
     */
    @Override
    public DERObject getDERObject() {
        
        return this.generalizedTime;
    }

}
