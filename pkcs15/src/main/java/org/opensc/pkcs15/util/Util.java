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
 * Created: 26.12.2008
 * 
 ***********************************************************/

package org.opensc.pkcs15.util;

/**
 * Static helper functions.
 * 
 * @author wglas
 */
public abstract class Util {

    /**
     * @param b A byte array to be formatted.
     * @return A string of length <code>b.length*2+b.length-1</code> consisting of
     *         hexadecimal representations of each byte in <code>b</code>
     *         separated by ':'.
     */
    static public String asHex(byte[] b) {
        
        if (b==null) return null;
        
        StringBuffer sb = new StringBuffer(b.length*3);
        
        for (int i=0;i<b.length;++i) {
            
            if (i>0) sb.append(':');
            
            int iv = ((int)b[i]) & 0xff;
            
            if (iv < 0x10) sb.append('0');
            
            sb.append(Integer.toHexString(iv));
        }
        
        return sb.toString();
    }
    
    /**
     * @param b A byte array to be formatted.
     * @return A string of length <code>b.length*2+b.length-1</code> consisting of
     *         hexadecimal representations of each byte in <code>b</code>
     *         separated by ':'.
     */
    static public String asHexMask(int[] b) {
        
        if (b==null) return null;
        
        StringBuffer sb = new StringBuffer(b.length*6);
        
        for (int i=0;i<b.length;++i) {
            
            if (i>0) sb.append(':');
               
            int mask = (b[i]&0xff00) >> 8;
            
            if (mask == 0) {

                sb.append('*');
            }
            else {
                
                int iv = ((int)b[i]) & mask;
                if (iv < 0x10) sb.append('0');   
                sb.append(Integer.toHexString(iv));

                if (mask != 0xff) {
                    
                    sb.append('/');
                    if (mask < 0x10) sb.append('0');   
                    sb.append(Integer.toHexString(mask));
                }
            }
        }
        
        return sb.toString();
    }
}
