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
 * Created: 05.01.2009
 * 
 ***********************************************************/

package org.opensc.pkcs15.token;

import java.io.Serializable;
import java.util.Arrays;

import org.opensc.pkcs15.util.Util;

/**
 * @author wglas
 *
 */
public class TokenPath implements Serializable {

    private static final long serialVersionUID = -3849759447788334500L;

    private final int[] parts;
    
    /**
     * Crate a token path relative to the root of the token.
     * 
     * @param id The id of the token object.
     */
    public TokenPath(int id) {
        
        this.parts = new int[] { id };
    }
    
    /**
     * Crate a token path relative to the given path.
     * 
     * @param id The id of the token object.
     */
    public TokenPath(final TokenPath path, int id) {
        
        this.parts = Arrays.copyOf(path.parts,path.getLength()+1);
        this.parts[path.getLength()] = id;
    }

    /**
     * Construct a path as a copy of the given array of path
     * components given as MSB first pairs of bytes.
     * 
     * This subroutine does not check, whether the given byte array has
     * an even number of elements. If the number of element is odd, the
     * last byte is simply ignored.
     * 
     * @param ba The components of the new path.
     */
    public TokenPath(final byte[] ba) {
        
        int l = ba.length/2;
        this.parts = new int[l];
        
        for (int i=0; i<l; ++i) {

            this.parts[i] = ((((int)ba[2*i])&0xff) << 8) | (((int)ba[2*i+1])&0xff);
        }
    }

    /**
     * Construct a path as a copy of the given array of path
     * components. This constructor is protected, because directly
     * passing in the array possibly violates the immutability of this class.
     * 
     * @param ids The components of the new path.
     */
    protected TokenPath(final int[] ids) {
        
        this.parts = ids;
    }

    /**
     * @return The parent of this path.
     */
    public TokenPath getParent() {
        
        return new TokenPath(Arrays.copyOf(this.parts,this.parts.length-1));
    }
    
    /**
     * @return The last path id of this token.
     */
    public int getTailID() {
        return this.parts[this.parts.length-1];
    }
    
    /**
     * @param The ordinal of the path Id to retrieve.
     * @return The IDs of the path segment no. <code>i</code>.
     */
    public int getID(int i) {
        return this.parts[i];
    }
    
    /**
     * @return The number of IDs in this path.
     */
    public int getLength() {
        
        return this.parts.length;
    }
    
    /**
     * Convert the path to a MSB-first aligned byte array of pairs
     * of bytes.
     * 
     * An example is given below:
     * <pre>
     *   {0x3F00,0x5015}.toByteArray() = { 0x3F,0x00,0x50,0x15 }
     * </pre>
     * 
     * @return The path formatted as a MSB-first aligned byte array of pairs
     *         of bytes.
     */
    public byte[] toByteArray() {
        
        byte[] ret = new byte[this.parts.length * 2];
        
        for (int i=0; i<this.parts.length; ++i) {
            
            ret[2*i]   = (byte)(this.parts[i]>>8);
            ret[2*i+1] = (byte)(this.parts[i]);
            
        }
        return ret;
    }

    /**
     * Append a string representation to the given StringBuffer.
     * 
     * @param sb the string buffer to append to.
     */
    public void appendToStringBuffer(StringBuffer sb) {
        
        for (int i=0;i<this.parts.length;++i)
        {
            if (i > 0) sb.append('/');
            Util.appendHexByte(sb,this.parts[i]>>8); 
            Util.appendHexByte(sb,this.parts[i]); 
        }
      
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        
        StringBuffer sb = new StringBuffer();
        
        this.appendToStringBuffer(sb);
     
        return sb.toString();
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(this.parts);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        TokenPath other = (TokenPath) obj;
        return Arrays.equals(this.parts, other.parts);
    }
}
