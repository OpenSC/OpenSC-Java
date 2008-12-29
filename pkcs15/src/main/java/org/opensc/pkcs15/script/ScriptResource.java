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
 * Created: 27.12.2008
 * 
 ***********************************************************/

package org.opensc.pkcs15.script;

import java.io.IOException;
import java.io.InputStream;

/**
 * A resource, which may be opened as an {@link InputStream} and may open another resource
 * using a relative path, which is needed to handle include files in scripts.
 * 
 * @author wglas
 */
public interface ScriptResource {

    /**
     * @return The content of the script resource as an input stream.
     * @throws IOException Upon I/O errors.
     */
    public InputStream asInputStream() throws IOException;
    
    /**
     * @return Whether this resource exists.
     */
    public boolean exists();
    
    /**
     * @param relPath A relative path using <code>/</code> as separator.
     * @return A script resource representing the relative path to this resource. 
     * @throws IOException Upon I/O errors.
     */
    public ScriptResource openInclude(String relPath) throws IOException;
}
