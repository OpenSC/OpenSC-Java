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

import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERGeneralizedTime;

/**
 * This interface is needed as a facade for bouncycastle's
 * {@link DERGeneralizedTime} class in order to build generate
 * <code>ReferencedValue{GeneralizedTime}</code> proxies.
 * 
 * @author wglas
 */
public interface GeneralizedTimeHolder extends DEREncodable {

    /**
     * @return The ASN.1 generalized time hold by this instance.
     */
    public DERGeneralizedTime getGeneralizedTime();
    
    /**
     * @param generalizedTime the ASN.1 gerneralized time to hold.
     */
    public void setGeneralizedTime(DERGeneralizedTime generalizedTime);
}
