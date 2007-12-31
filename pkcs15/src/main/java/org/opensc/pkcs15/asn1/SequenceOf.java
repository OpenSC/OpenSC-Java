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
 * Created: 31.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1;

import java.util.List;

import org.bouncycastle.asn1.DEREncodable;

/**
 * An ASN.1 SEQUENCE OF, which may be read from an InputStream in
 * or to decode referenced <code>PathOrObjects</code> instances.
 * 
 * @author wglas
 *
 * @param <EntityType>
 */
public interface SequenceOf<EntityType extends DEREncodable> extends DEREncodable {

    /**
     * @return the sequence
     */
    public List<EntityType> getSequence();

    /**
     * @param sequence the sequence to set
     */
    public void setSequence(List<EntityType> sequence);

    /**
     * @param e The element to add to the internal sequence.
     */
    public void addEntity(EntityType e);

}