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

package org.opensc.pkcs15.script.impl;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.opensc.pkcs15.script.ClassPathScriptResource;
import org.opensc.pkcs15.script.FileScriptResource;
import org.opensc.pkcs15.script.ScriptResource;
import org.opensc.pkcs15.script.ScriptResourceFactory;

/**
 * The default script resource factory implementation.
 * 
 * @author wglas
 */
public class ScriptResourceFactoryImpl extends ScriptResourceFactory {

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.script.ScriptResourceFactory#getScriptResource(java.lang.String)
     */
    @Override
    public ScriptResource getScriptResource(String schemeAndPath) throws IOException {
        
        int cp = schemeAndPath.indexOf(':');
        
        if (cp < 0)
            throw new IOException("The identifier ["+schemeAndPath+"] contains no colon.");
        
        return this.getScriptResource(schemeAndPath.substring(0,cp),schemeAndPath.substring(cp+1));
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.script.ScriptResourceFactory#getScriptResource(java.lang.String, java.lang.String)
     */
    @Override
    public ScriptResource getScriptResource(String scheme, String path) throws IOException {
        
        if ("file".equals(scheme))
            return new FileScriptResource(new File(path));
        
        if ("classpath".equals(scheme))
            return new ClassPathScriptResource(Thread.currentThread().getContextClassLoader(),path);
        
        throw new FileNotFoundException("Unsupported scheme ["+scheme+"].");
    }

}
