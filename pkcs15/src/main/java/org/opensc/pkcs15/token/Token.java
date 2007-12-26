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
 * Created: 25.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15.token;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * An abstraction of a cryptographic token, either a hardware token or
 * a software token.
 * 
 * @author wglas
 */
public interface Token {

    TokenFile getCurrentFile() throws IOException;
    
    TokenFile select(int path) throws IOException;
    
    DF selectDF(int path) throws IOException;
    
    EF selectEF(int path) throws IOException;
    
    MF selectMF() throws IOException;
    
    InputStream readEFData() throws IOException;
    
    OutputStream writeEFData() throws IOException;
    
    EF createEF(int path, EFAcl acl) throws IOException;
    
    DF createDF(int path, DFAcl acl) throws IOException;
    
    void close() throws IOException;
}
