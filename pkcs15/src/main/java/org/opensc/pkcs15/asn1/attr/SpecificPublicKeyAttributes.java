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

package org.opensc.pkcs15.asn1.attr;

import org.bouncycastle.asn1.DEREncodable;
import org.opensc.pkcs15.asn1.basic.KeyInfo;
import org.opensc.pkcs15.asn1.basic.Operations;
import org.opensc.pkcs15.asn1.proxy.ReferenceProxy;

/**
 * All <code>Public*KeyAttributes</code> objects fulfill this interface 
 * 
 * @author wglas
 */
public interface SpecificPublicKeyAttributes extends DEREncodable {

    /**
     * @return The stored public key object on the token. Please note,
     *         that it is likely, that the returned object is an instance
     *         of {@link ReferenceProxy}, if it originated from a
     *         <code>ReferencedValue{PublicKeyObject}</code>, which
     *         points to a <code>Path</code> or an <code>URL</code>.
     */
    public PublicKeyObject getPublicKeyObject();

    /**
     * @return The KeyInfo object stored for the public key.
     *         All KeyInfo's have the second type parameter set
     *         to {@link Operations}, so this parameter is tied by
     *         this method. The first type parameter is dependent on the
     *         cryptographic algorithm performed by the public  key.   
     */
    public KeyInfo<? extends DEREncodable, Operations> getGenericKeyInfo();

}