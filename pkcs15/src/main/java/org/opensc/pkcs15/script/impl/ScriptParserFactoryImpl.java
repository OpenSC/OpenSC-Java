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
 * Created: 29.12.2008
 * 
 ***********************************************************/

package org.opensc.pkcs15.script.impl;

import org.opensc.pkcs15.script.ScriptParser;
import org.opensc.pkcs15.script.ScriptParserFactory;

/**
 * The default script parser factory implementation.
 * 
 * @author wglas
 */
public class ScriptParserFactoryImpl extends ScriptParserFactory {

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.script.ScriptParserFactory#getScriptParser(java.lang.String)
     */
    @Override
    public ScriptParser getScriptParser(String type) {
       
        if ("ser".equals(type))
            return new SERScriptParser();
        
        if ("csf".equals(type))
            return new CSFScriptParser();
        
       return null;
    }

}
