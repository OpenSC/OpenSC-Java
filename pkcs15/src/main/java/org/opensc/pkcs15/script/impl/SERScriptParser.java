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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.opensc.pkcs15.script.Command;
import org.opensc.pkcs15.script.ScriptParser;
import org.opensc.pkcs15.script.ScriptResource;

/**
 * A script parser, which parses a script serialized through {@link ObjectOutputStream}. 
 * 
 * @author wglas
 */
public class SERScriptParser implements ScriptParser {

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.script.ScriptParser#parseScript(org.opensc.pkcs15.script.ScriptResource)
     */
    @Override
    public Command parseScript(ScriptResource resource) throws IOException {
       
        ObjectInputStream ois = new ObjectInputStream(resource.asInputStream());
        
        try {
            Object obj = ois.readObject();
            
            if (!(obj instanceof Command))
                throw new IOException("Invalid object ["+obj.getClass()+"] in serialized script ["+resource+"].");
                
            return (Command)obj;
            
        } catch (ClassNotFoundException e) {
            throw new IOException("Failed to load a serialized class",e);
        }
    }
}
