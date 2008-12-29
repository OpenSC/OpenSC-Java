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
 * A script resource, which resides on the class path.
 * 
 * @author wglas
 */
public class ClassPathScriptResource implements ScriptResource {

    private final ClassLoader classLoader;
    private final String path;
    
    /**
     * @param classLoader The class loader on which to find the resource.
     * @param path The class path of the resource.
     */
    public ClassPathScriptResource(ClassLoader classLoader, String path) {
        super();
        this.classLoader = classLoader;
        this.path = path;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.script.ScriptResource#asInputStream()
     */
    @Override
    public InputStream asInputStream() throws IOException {
        
        return this.classLoader.getResourceAsStream(this.path);
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.script.ScriptResource#exists()
     */
    @Override
    public boolean exists() {
       
        return this.classLoader.getResource(this.path) != null;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.script.ScriptResource#openInclude(java.lang.String)
     */
    @Override
    public ScriptResource openInclude(String relPath) throws IOException {
      
        int sep = this.path.lastIndexOf('/');
        
        String newPath;
        
        if (sep >= 0)
            newPath = this.path.substring(0,sep+1) + relPath;
        else
            newPath = relPath;
        
        return new ClassPathScriptResource(this.classLoader,newPath);
    }

    /**
     * @return the class loader used to search this resource.
     */
    public ClassLoader getClassLoader() {
        return this.classLoader;
    }

    /**
     * @return the path on the class loader of this resource.
     */
    public String getPath() {
        return this.path;
    }

    public String toString() {

        return "classpath:"+this.path;
    }
}
