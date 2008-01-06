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

package org.opensc.pkcs15.asn1.proxy;

import org.bouncycastle.asn1.DEREncodable;

/**
 * A marker interface for explicitly resolving the referenced entity.
 * Any value, that is stored as a <code>ReferncedValue{EntityType}</code> on
 * the token, will be returned as a proxy to the <code>EntityType</code>
 * interface. The returned proxy will always implement the <code>ReferenceProxy</code>
 * interface in order to allow updating the referenced EF of URL or to get access to
 * the proxied implementation of the <code>EntityType</code> interface.
 * 
 * A proxy to an entity is serialized as the entity (<code>Path</code> or <code>URL</code>
 * and not as the contents of the entity, i.e. the method {@link DEREncodable#getDERObject()}
 * is overwritten for the proxy to return the reference instead of the implementation.
 * 
 * You can get the actual implementation, which is serialized as the contents of the
 * referenced entity by callig {@link #resolveEntity()}.
 * 
 * @param <EntityType> The interface of the application object.
 * 
 * @see ReferenceProxyFactory
 * 
 * @author wglas
 */
public interface ReferenceProxy<EntityType extends DEREncodable> extends DEREncodable {

    /**
     * @return The delegate, which is hidden by this proxy.
     */
    public EntityType resolveEntity();

    /**
     * Update the referenced entity.
     */
    public void updateEntity();
}
