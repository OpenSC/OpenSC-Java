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

/**
 * static helper functions for path manipulations.
 * 
 * @author wglas
 */
public abstract class PathHelper {

    /**
     * The path of the master file on a token.
     */
    public static final byte[] MF_PATH = new byte[] { 0x3F, 0x00 };
    public static final int MF_ID = 0x3F00;
    
    private static final char[] HEX_DIGITS =
        new char[] {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    
    private static void appendHexByte(StringBuffer sb, int b)
    {
        sb.append(HEX_DIGITS[(b>>4)&0x0f]);
        sb.append(HEX_DIGITS[b&0x0f]);
    }
    
    /**
     * @param id A file ID consisting of 2 unsigned bytes.
     * @return A string consisting of 4 hex digits.
     */
    public static String formatID(int id)
    {
        StringBuffer sb = new StringBuffer();
        appendHexByte(sb,id>>8);
        appendHexByte(sb,id);
        return sb.toString();
    }
    
    /**
     * @param path A path consisting of pairs of bytes.
     * @return A string with slash-separated IDs.
     */
    public static String formatPath(final byte [] path)
    {
        StringBuffer sb = new StringBuffer();
        
        int l = 0;
        
        while (l<path.length)
        {
            if (l > 0) sb.append('/');
            appendHexByte(sb,path[l]); 
            appendHexByte(sb,path[l+1]); 
            l+=2;
        }
     
        return sb.toString();
    }
    
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
     * Append an ID to a path.
     * 
     * The bytes appended to the path are <code>(byte)(id >> 8)</code>
     * and <code>(byte)id</code> in order.
     * 
     * @param path A path consisting of pairs of bytes.
     * @param id The two-byte ID of the child element.
     * @return A path with the two byte appended.
     */
    public static byte[] appendToPath(final byte [] path, final int id)
    {
        byte[] ret = new byte[path.length+2];
        
        System.arraycopy(path,0,ret,0,path.length);
        ret[path.length] = (byte)(id >> 8);
        ret[path.length+1] = (byte)id;
        return ret;
    }

    /**
     * Change to the parent path.
     * 
     * @param path A path consisting of pairs of bytes.
     * @return A path truncated by the last two byte appended.
     * 
     * @throws IOException if the path is already the MF path.
     */
    public static byte[] truncatePath(final byte [] path) throws IOException
    {
        if (path.length <= 2)
            throw new IOException("Cannot change to directory bove MF.");
        
        byte[] ret = new byte[path.length-2];
        
        System.arraycopy(path,0,ret,0,path.length-2);
        return ret;
    }

    /**
     * @param path A path consisting of pairs of bytes.
     * @return The ID of the last file at the given byte position in the path.
     */
    public static int idAt(final byte [] path, int pos)
    {
        return ((((int)path[pos])&0xff) << 8) | (((int)path[pos+1])&0xff);
    }
    
    /**
     * @param path A path consisting of pairs of bytes.
     * @return The ID of the last file in the path comprised of the last two bytes in the path.
     */
    public static int tailID(final byte [] path)
    {
       return idAt(path,path.length-2);
    }
    
    /**
     * @param path1 A first path consisting of pairs of bytes.
     * @param path2 A second path consisting of pairs of bytes.
     * @return The length of the common trunk of the two path'.
     */
    public static int commonTrunkLength(final byte [] path1, final byte [] path2)
    {
        int l = 0;
        
        while (l<path1.length && l<path2.length)
        {
            if (path1[l] != path2[l] ||
                    path1[l+1] != path2[l+1])
                break;
                
            l+=2;
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
    public static TokenFile select(Token token, final byte [] path) throws IOException
    {
        TokenFile current = token.getCurrentFile();
        
        if (current == null) {
            current = token.selectMF();
        } 
        
        // find common trunk.
        int l = commonTrunkLength(current.getPath(),path);
          
        if (l <2)
            throw new IOException("The path ["+formatPath(path)+"] is not a subpath of the MF.");
        
        // chdir up.
        while (current.getPath().length > l)
            current = token.selectParentDF();
        
        // chdir down.
        while (current.getPath().length < path.length)
        {
            current = token.select(idAt(path,current.getPath().length));
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
    public static EF selectEF(Token token, final byte [] path) throws IOException
    {
        TokenFile current = token.getCurrentFile();
        
        if (current == null) {
            current = token.selectMF();
        }
        
        // find common trunk.
        int l = commonTrunkLength(current.getPath(),path);
        
        if (l <2)
            throw new IOException("The path ["+formatPath(path)+"] is not a subpath of the MF.");

        if (l==path.length && l == current.getPath().length) {
            
            if (current instanceof EF)
                return (EF)current;
            
            throw new IOException("The current file ["+formatPath(path)+"] is not an EF.");
        }
            
        // chdir up.
        while (current.getPath().length > l)
            current = token.selectParentDF();
        
        // chdir down.
        while (current.getPath().length < path.length-2)
        {
            current = token.select(idAt(path,current.getPath().length));
        }
            
        return token.selectEF(idAt(path,path.length-2));
    }
    
    /**
     * Select an dedicated file by an absolute path.
     * 
     * @param token A token.
     * @param path An absolute path.
     * @return The DF at the given absolute path.
     * @throws IOException Upon I/O errors from the token.
     */
    public static DF selectDF(Token token, final byte [] path) throws IOException
    {
        TokenFile current = token.getCurrentFile();
        
        if (current == null) {
            current = token.selectMF();
        }

        // find common trunk.
        int l = commonTrunkLength(current.getPath(),path);
        
        if (l <2)
            throw new IOException("The path ["+formatPath(path)+"] is not a subpath of the MF.");

        if (l==path.length && l == current.getPath().length) {
            
            if (current instanceof DF)
                return (DF)current;
            
            throw new IOException("The current file ["+formatPath(path)+"] is not a DF.");
        }
            
        // chdir up.
        while (current.getPath().length > l)
            current = token.selectParentDF();
        
        
        // chdir down.
        while (current.getPath().length < path.length-2)
        {
            current = token.select(idAt(path,current.getPath().length));
        }
            
        return token.selectDF(idAt(path,path.length-2));
    }
}
