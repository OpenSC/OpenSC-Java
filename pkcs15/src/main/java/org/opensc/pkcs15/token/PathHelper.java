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
 * Created: 29.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15.token;

import java.io.IOException;

import org.opensc.pkcs15.util.Util;

/**
 * static helper functions for path manipulations.
 * 
 * @author wglas
 */
public abstract class PathHelper {

    /**
     * The path of the master file on a token.
     */
    public static final int MF_ID = 0x3F00;
    public static final TokenPath MF_PATH = new TokenPath(MF_ID);
    
    /**
     * @param id A file ID consisting of 2 unsigned bytes.
     * @return A byte array containing two bytes. 
     */
    public static byte[] idToPath(int id)
    {
        byte [] ret = new byte[2];
        ret[0] = (byte) (id>>8);
        ret[1] = (byte)id;
        return ret;
    }

    /**
     * Append four hex digits of an unsigned file ID to the given string buffer. 
     * 
     * @param sb A string buffer to format to.
     * @param id A file ID consisting of 2 unsigned bytes.
     */
    public static void appendIDToStringBuffer(StringBuffer sb, int id) {
        Util.appendHexByte(sb,id>>8);
        Util.appendHexByte(sb,id);
    }
    
    /**
     * Return a string of four hex digits for an unsigned file ID. 
     * 
     * @param id A file ID consisting of 2 unsigned bytes.
     * @return A string consisting of 4 hex digits.
     */
    public static String formatID(int id)
    {
        StringBuffer sb = new StringBuffer();
        appendIDToStringBuffer(sb,id);
        return sb.toString();
    }
    
    /**
     * @param path1 A first path consisting of pairs of bytes.
     * @param path2 A second path consisting of pairs of bytes.
     * @return The length of the common trunk of the two path'.
     */
    public static int commonTrunkLength(final TokenPath path1, final TokenPath path2)
    {
        int l;
        
        for (l=0; l<path1.getLength() && l<path2.getLength(); ++l)
        {
            if (path1.getID(l) != path2.getID(l))
                break;
        }

        return l;
    }
    
    /**
     * Select a token file by an absolute path.
     * 
     * @param token A token.
     * @param path An absolute path.
     * @return The file at the given absolute path.
     * @throws IOException Upon I/O errors from the token.
     */
    public static TokenFile select(Token token, final TokenPath path) throws IOException
    {
        TokenFile current = token.getCurrentFile();
        
        if (current == null) {
            current = token.selectMF();
        } 
        
        // find common trunk.
        int l = commonTrunkLength(current.getPath(),path);
          
        if (l <1)
            throw new IOException("The path ["+path+"] is not a subpath of the MF.");
        
        // chdir up.
        while (current.getPath().getLength() > l)
            current = token.selectParentDF();
        
        // chdir down.
        while (current.getPath().getLength() < path.getLength())
        {
            current = token.select(path.getID(current.getPath().getLength()));
        }
            
        return current;
    }
    
    /**
     * Select an elementary file by an absolute path.
     * 
     * @param token A token.
     * @param path An absolute path.
     * @return The EF at the given absolute path.
     * @throws IOException Upon I/O errors from the token.
     */
    public static EF selectEF(Token token, final TokenPath path) throws IOException
    {
        TokenFile current = token.getCurrentFile();
        
        if (current == null) {
            current = token.selectMF();
        }
        
        // find common trunk.
        int l = commonTrunkLength(current.getPath(),path);
        
        if (l<1)
            throw new IOException("The path ["+path+"] is not a subpath of the MF.");

        if (l == path.getLength() && l == current.getPath().getLength()) {
            
            if (current instanceof EF)
                return (EF)current;
            
            throw new IOException("The current file ["+path+"] is not an EF.");
        }
            
        // chdir up.
        while (current.getPath().getLength() > l)
            current = token.selectParentDF();
        
        // chdir down.
        while (current.getPath().getLength() < path.getLength()-1)
        {
            current = token.select(path.getID(current.getPath().getLength()));
        }
            
        return token.selectEF(path.getTailID());
    }
    
    /**
     * Select an dedicated file by an absolute path.
     * 
     * @param token A token.
     * @param path An absolute path.
     * @return The DF at the given absolute path.
     * @throws IOException Upon I/O errors from the token.
     */
    public static DF selectDF(Token token, final TokenPath path) throws IOException
    {
        TokenFile current = token.getCurrentFile();
        
        if (current == null) {
            current = token.selectMF();
        }

        // find common trunk.
        int l = commonTrunkLength(current.getPath(),path);
        
        if (l<1)
            throw new IOException("The path ["+path+"] is not a subpath of the MF.");

        if (l==path.getLength() && l == current.getPath().getLength()) {
            
            if (current instanceof DF)
                return (DF)current;
            
            throw new IOException("The current file ["+path+"] is not a DF.");
        }
            
        // chdir up.
        while (current.getPath().getLength() > l)
            current = token.selectParentDF();
        
        
        // chdir down.
        while (current.getPath().getLength() < path.getLength()-1)
        {
            current = token.select(path.getID(current.getPath().getLength()-1));
        }
            
        return token.selectDF(path.getTailID());
    }

    /**
     * Format the string of a subpath to the given path.
     * 
     * This method eases the implementation of log messages.
     * 
     * @param path The parent path.
     * @param id The relative path component.
     * @return A string consisting of the parent path, a slash and the formatted id.
     */
    public static String formatPathAppend(TokenPath path, int id) {
       
        StringBuffer sb = new StringBuffer();
        
        path.appendToStringBuffer(sb);
        sb.append('/');
        appendIDToStringBuffer(sb,id);
        return sb.toString();
    }
}
