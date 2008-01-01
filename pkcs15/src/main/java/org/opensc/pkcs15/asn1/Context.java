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

package org.opensc.pkcs15.asn1;

import org.bouncycastle.asn1.DERInteger;
import org.opensc.pkcs15.asn1.attr.RSAPrivateKeyObject;
import org.opensc.pkcs15.asn1.attr.RSAPublicKeyObject;
import org.opensc.pkcs15.asn1.attr.X509CertificateObject;
import org.opensc.pkcs15.asn1.basic.RSAKeyInfo;
import org.opensc.pkcs15.asn1.proxy.Directory;
import org.opensc.pkcs15.asn1.ref.Path;

/**
 * This interface represents a context for deserializing references.
 * 
 * @author wglas
 */
public interface Context {

    public Directory<Path,RSAPrivateKeyObject> getRSAPrivateKeyDirectory();

    public Directory<Path, RSAPublicKeyObject> getRSAPublicKeyDirectory();
    
    public Directory<DERInteger,RSAKeyInfo> getRSAKeyInfoDirectory();
    
    public Directory<Path, X509CertificateObject> getX509CertificateDirectory();
}
