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
 * Created: 31.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1.basic;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;

/**
 * An implementation of RSAKeyInfo.
 * 
 * @author wglas
 */
public class RSAKeyInfoImpl extends KeyInfoImpl<DERNull, Operations> implements RSAKeyInfo {

    /**
     * Default constructor.
     */
    public RSAKeyInfoImpl() {
        super(DERNull.INSTANCE,null);
    }

    /**
     * @param parameters
     * @param supportedOperations
     */
    public RSAKeyInfoImpl(Operations supportedOperations) {
        super(DERNull.INSTANCE, supportedOperations);
    }

    /**
     * This method implements the static getInstance factory pattern. 
     * 
     * @param obj ASN.1 object to be decoded.
     * @return A KeyInfoImpl object suitable for RSA Private keys.
     */
    static public RSAKeyInfoImpl getInstance(Object obj)
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(obj);
        
        return getInstanceFromSequence(seq.getObjects());
    }

    /**
     * This method is used in order to parse the
     * <code>parameters</code> and <code>supportedOperations</code> member of
     * an <code>AlgorithmInfo</code> for the RSA algorithm.
     * 
     * @param objs The members of an ASN.1 sequence positioned at the element before
     *             the <code>RSAKeyInfo</code> member.
     * @return A KeyInfo object suitable for RSA Private keys.
     */
    static public RSAKeyInfoImpl getInstanceFromSequence(Enumeration<Object> objs)
    {
        if (!objs.hasMoreElements())
            throw new IllegalArgumentException("RSAKeyInfo consists of at least one sequence member.");
        
        Object o = objs.nextElement();
        Operations ops;
        
        if (o instanceof ASN1Sequence || o instanceof Operations) {
            ops = Operations.getInstance(o);
        } else {
            if (!(o instanceof ASN1Null))
                throw new IllegalArgumentException("RSAKeyInfo does neither start with Operations nor with NULL.");
            
            // ignore null before operations.
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("RSAKeyInfo consists of at least two sequence members.");
            
            o = objs.nextElement();
            ops = Operations.getInstance(o);
        }
        
        return new RSAKeyInfoImpl(ops);
    }
}
