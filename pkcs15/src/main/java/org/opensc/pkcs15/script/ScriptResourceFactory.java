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

import javax.imageio.spi.ServiceRegistry;

/**
 * A scipt resource factory.
 * 
 * @author wglas
 */
public abstract class ScriptResourceFactory {
    
    /**
     * @return The script resource factory registered under
     *   <code>META-INF/services/org.opensc.pkcs15.script.ScriptResourceFactory</code>.
     */
    static public ScriptResourceFactory getInstance() {
        
        return ServiceRegistry.lookupProviders(ScriptResourceFactory.class).next();
    }
    
    /**
     * Construct a resource from a colon-separated scheme and path.
     * 
     * Currently supported are <code>file:/some/fs/sample.script</code> and
     * <code>classpath:org/example/scripts/sample.script</code>.
     * 
     * @param schemeAndPath A schema, a colon and a path.
     * @return A script resource of the given scheme and path.
     */
    public abstract ScriptResource getScriptResource(String schemeAndPath) throws IOException;
    
    /**
     * Construct a resource from a scheme and a path.
     * 
     * <urrently supported schems are <code>file</code> and
     * <code>classpath</code>.
     * 
     * @param scheme The scheme
     * @param path The path of the resource.
     * @return A script resource of the given scheme and path.
     */
    public abstract ScriptResource getScriptResource(String scheme, String path) throws IOException;
}
