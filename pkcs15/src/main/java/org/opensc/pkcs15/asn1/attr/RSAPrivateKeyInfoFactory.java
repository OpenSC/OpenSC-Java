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
 * Created: 30.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1.attr;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.opensc.pkcs15.asn1.basic.Operations;
import org.opensc.pkcs15.asn1.basic.RSAKeyInfo;
import org.opensc.pkcs15.asn1.basic.RSAKeyInfoImpl;
import org.opensc.pkcs15.asn1.proxy.Directory;
import org.opensc.pkcs15.asn1.proxy.ReferenceProxyFactory;

/**
 * A factory which instantiates KeyInfo instances as used by RSA private keys. 
 * 
 * <PRE>
 * KeyInfo {NULL, PublicKeyOperations} 
 * </PRE>
 * 
 * where
 * 
 * <PRE>
 * KeyInfo {ParameterType, OperationsType} ::= CHOICE {
 *       reference           Reference,
 *       paramsAndOps        SEQUENCE {
 *           parameters      ParameterType,
 *           supportedOperations OperationsType OPTIONAL
 *          }
 *       }
 * </PRE>
 *
 * @author wglas
 */
public abstract class RSAPrivateKeyInfoFactory {

    private static ReferenceProxyFactory<DERInteger,RSAKeyInfo>
    proxyFactory =
        new ReferenceProxyFactory<DERInteger,RSAKeyInfo>(RSAKeyInfo.class);
    
    /**
     * @param obj ASN.1 object to be decoded.
     * @param directory A directory for resolving integer references.
     * @return A KeyInfo object suitable for RSA Private keys.
     */
    static public RSAKeyInfo getInstance(Object obj,
            Directory<DERInteger,RSAKeyInfo> directory)
    {
        if (obj instanceof RSAKeyInfo) {
            return (RSAKeyInfo) obj;
        }
        
        if (obj instanceof DERInteger) {
            return proxyFactory.getProxy((DERInteger)obj,directory);
        }
        
        ASN1Sequence seq = ASN1Sequence.getInstance(obj);
        
        Enumeration<Object> objs = seq.getObjects();
        
        if (!objs.hasMoreElements())
            throw new IllegalArgumentException("KeyInfo consists of at least one sequence member.");
        
        Object o = objs.nextElement();
        Operations ops;
        
        if (o instanceof ASN1Sequence || o instanceof Operations) {
            ops = Operations.getInstance(o);
        } else {
            // ignore null before operations.
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("KeyInfo consists of at least two sequence members.");
            
            o = objs.nextElement();
            ops = Operations.getInstance(o);
        }
        
        return new RSAKeyInfoImpl(ops);
    }
    
}
