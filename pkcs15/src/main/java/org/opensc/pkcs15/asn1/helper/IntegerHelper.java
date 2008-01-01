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
 * Created: 01.01.2008
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1.helper;

import java.math.BigInteger;

/**
 * static helpers for manipulating integer values.
 * 
 * @author wglas
 */
public abstract class IntegerHelper {

    private static BigInteger MIN_INT_BIG_INTEGER = BigInteger.valueOf(Integer.MIN_VALUE);
    private static BigInteger MAX_INT_BIG_INTEGER = BigInteger.valueOf(Integer.MAX_VALUE);
    
    /**
     * Converts a BigInteger to an integer, if the BigInteger is
     * in the correct range. Otherwise, an IllegalArgumentException is thrown.
     * 
     * @param bi The BigInteger to convert.
     * @return The integer value.
     */
    public static int intValue(BigInteger bi) 
    {
        if (bi.compareTo(MIN_INT_BIG_INTEGER) < 0)
            throw new IllegalArgumentException("BigInteger ["+bi+"] is too small to convert to int.");
        if (bi.compareTo(MAX_INT_BIG_INTEGER) > 0)
            throw new IllegalArgumentException("BigInteger ["+bi+"] is too big to convert to int.");
        
        return bi.intValue();
    }
    
    /**
     * Converts a BigInteger to an integer, if the BigInteger is
     * in the correct range. Otherwise, an IllegalArgumentException is thrown.
     * 
     * This method is null-aware.
     * 
     * @param bi The BigInteger to convert.
     * @return The integer value.
     */
    public static Integer toInteger(BigInteger bi) 
    {
        if (bi == null) return null;
        
        if (bi.compareTo(MIN_INT_BIG_INTEGER) < 0)
            throw new IllegalArgumentException("BigInteger ["+bi+"] is too small to convert to int.");
        if (bi.compareTo(MAX_INT_BIG_INTEGER) > 0)
            throw new IllegalArgumentException("BigInteger ["+bi+"] is too big to convert to int.");
        
        return bi.intValue();
    }
}
