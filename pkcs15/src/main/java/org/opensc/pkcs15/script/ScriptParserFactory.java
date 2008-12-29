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

import javax.imageio.spi.ServiceRegistry;

/**
 * A scipt resource factory.
 * 
 * @author wglas
 */
public abstract class ScriptParserFactory {
    
    /**
     * @return The script resource factory registered under
     *   <code>META-INF/services/org.opensc.pkcs15.script.ScriptParserFactory</code>.
     */
    static public ScriptParserFactory getInstance() {
        
        return ServiceRegistry.lookupProviders(ScriptParserFactory.class).next();
    }
    
    /**
     * Construct a script parser for a script type.
     * 
     * Currently supported types are <code>ser</code> for JAVA-serialized
     * scripts and <code>csf</code> for Siemens-style APSU scripts.
     * 
     * @param type A script type.
     * @return A script parser.
     */
    public abstract ScriptParser getScriptParser(String type);

}
