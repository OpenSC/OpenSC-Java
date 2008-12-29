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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * A script resource that can be found in the file system.
 * 
 * @author wglas
 */
public class FileScriptResource implements ScriptResource {

    private final File file;
    
    /**
     * @param file
     */
    public FileScriptResource(File file) {
        super();
        this.file = file;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.script.ScriptResource#asInputStream()
     */
    @Override
    public InputStream asInputStream() throws IOException {
      
        return new FileInputStream(this.file);
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.script.ScriptResource#exists()
     */
    @Override
    public boolean exists() {
        
        return this.file.exists() && this.file.isFile();
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.script.ScriptResource#openInclude(java.lang.String)
     */
    @Override
    public ScriptResource openInclude(String relPath) throws IOException {
        
        if (new File(relPath).isAbsolute())
            throw new IOException("The given path ["+relPath+"] is not relative.");
        
        if (relPath.contains(".."))
            throw new IOException("The given path ["+relPath+"] tries to escape the directory hierarchy.");
        
        return new FileScriptResource(new File(this.file.getParent(),relPath));
    }

    /**
     * @return the underlying file of this resource. 
     */
    public File getFile() {
        return this.file;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    public String toString() {
        
        return "file:"+this.file.getAbsolutePath();
    }
}
