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

import org.bouncycastle.asn1.DERInteger;
import org.opensc.pkcs15.asn1.Context;
import org.opensc.pkcs15.asn1.ContextHolder;
import org.opensc.pkcs15.asn1.basic.NullKeyInfo;
import org.opensc.pkcs15.asn1.basic.NullKeyInfoImpl;
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
public abstract class RSAKeyInfoFactory {

    private static ReferenceProxyFactory<DERInteger,NullKeyInfo>
    proxyFactory =
        new ReferenceProxyFactory<DERInteger,NullKeyInfo>(NullKeyInfo.class);
    
    /**
     * This method implements the static getInstance factory pattern by
     * using the thread-local context stored in {@link ContextHolder}. 
     * 
     * @param obj ASN.1 object to be decoded.
     * @return A KeyInfo object suitable for RSA Private keys.
     */
    static public NullKeyInfo getInstance(Object obj)
    {
        Context context = ContextHolder.getContext();
        
        Directory<DERInteger,NullKeyInfo> directory =
            context == null ? null : context.getNullKeyInfoDirectory();
        
        return getInstance(obj,directory);
    }
            
    /**
     * @param obj ASN.1 object to be decoded.
     * @param directory A directory for resolving integer references.
     * @return A KeyInfo object suitable for RSA Private keys.
     */
    static public NullKeyInfo getInstance(Object obj,
            Directory<DERInteger,NullKeyInfo> directory)
    {
        if (obj instanceof NullKeyInfo) {
            return (NullKeyInfo) obj;
        }
        
        if (obj instanceof DERInteger) {
            return proxyFactory.getProxy((DERInteger)obj,directory);
        }
        
        return NullKeyInfoImpl.getInstance(obj);
    }
}
