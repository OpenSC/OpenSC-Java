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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.DEREncodable;

/**
 * A directory for resolving references, as e.g. implemented by
 * TokenInfo.
 * 
 * @author wglas
 */
public interface StreamResolver<ReferenceType extends DEREncodable> {

    /**
     * @param ref The reference to resolve.
     * @return An InputStream which reads from the resolved entity. 
     * @throws IOException 
     */
    InputStream readReference(ReferenceType ref) throws IOException;
    
    /**
     * @param ref The reference to store to.
      * @return An OutputStream which writes to the resolved entity.
     */
    OutputStream writeReference(ReferenceType ref) throws IOException;
    
}
