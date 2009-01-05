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

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * An abstraction of a cryptographic token, either a hardware token or
 * a software token.
 * 
 * @author wglas
 */
public interface Token extends Closeable {

    /**
     * Reset the token to the state, where only the master file (MF) exists.
     * 
     * Hardware token implementations should take care to execute a script,
     * which undertakes the necessary steps on the card depending on the state
     * of the card.
     */
    void reset() throws IOException;
    
    /**
     * @return The current file on the token.
     * @throws IOException Upon errors.
     */
    TokenFile getCurrentFile() throws IOException;
    
    /**
     * Select a file (DF or EF), which is a child of the current DF.
     * 
     * @param path The relative path of the child to open.
     * @return The new current file on the token.
     * @throws IOException Upon errors.
     */
    TokenFile select(int path) throws IOException;
    
    /**
     * Select the parent DF of the current DF.
     * 
     * @return The parent DF, which is now the current file.
     * @throws IOException Upon errors.
     */
    DF selectParentDF() throws IOException;
    
    /**
     * Select a DF, which is a child of the current DF.
     * 
     * @param path The relative path of the DF to open.
     * @return The new current file on the token.
     * @throws IOException Upon card errors or when the selected file is not a DF.
     */
    DF selectDF(int path) throws IOException;
    
    /**
     * Select an EF, which is a child of the current DF.
     * 
     * @param path The relative path of the EF to open.
     * @return The new current file on the token.
     * @throws IOException Upon card errors or when the selected file is not an EF.
     */
    EF selectEF(int path) throws IOException;
    
    /**
     * Select the master file on the token.
     * 
     * @return The master file, which is now the current file.
     * @throws IOException Upon card errors.
     */
    MF selectMF() throws IOException;
    
    /**
     * Read the content of the current EF-
     * 
     * @return An input stream with the content of the current EF.
     * @throws IOException Upon card errors or when the current file is not an EF.
     */
    InputStream readEFData() throws IOException;
    
    /**
     * Write to the content of the current EF.
     * 
     * @return An output stream, which writes to the content of the current EF
     * @throws IOException Upon card errors or when the current file is not an EF.
     */
    OutputStream writeEFData() throws IOException;
    
    /**
     * Create an elementary file as child of the current DF.
     * 
     * @param path The relative path of the EF to create.
     * @param size The reserved size of the EF to be created.
     * @param acl The access control list to set.
     * @return The description of the created elementary file.
     * @throws IOException
     */
    EF createEF(int path, long size, EFAcl acl) throws IOException;
    
    /**
     * Create a dedicated file as child of the current DF.
     * 
     * @param path The relative path of the DF to create.
     * @param size The reserved size of the DF to be created.
     * @param acl The access control list to set.
     * @return The description of the created dedicated file.
     * @throws IOException
     */
    DF createDF(int path, long size, DFAcl acl) throws IOException;
    
    /**
     * Delete a dedicated file as child of the current DF.
     * 
     * @param path The relative path of the DF to delete.
     * @throws IOException
     */
    void deleteDF(int path) throws IOException;
    
    /**
     * Delete an elementary file as child of the current DF.
     * 
     * @param path The relative path of the EF to delete.
     * @throws IOException
     */
    void deleteEF(int path) throws IOException;
}
