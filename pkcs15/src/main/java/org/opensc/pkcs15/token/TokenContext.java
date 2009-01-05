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

package org.opensc.pkcs15.token;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.DERInteger;
import org.opensc.pkcs15.asn1.Context;
import org.opensc.pkcs15.asn1.attr.RSAKeyInfoFactory;
import org.opensc.pkcs15.asn1.attr.RSAPrivateKeyObject;
import org.opensc.pkcs15.asn1.attr.RSAPublicKeyChoice;
import org.opensc.pkcs15.asn1.attr.RSAPublicKeyObject;
import org.opensc.pkcs15.asn1.attr.X509CertificateObject;
import org.opensc.pkcs15.asn1.attr.X509CertificateObjectImpl;
import org.opensc.pkcs15.asn1.basic.NullKeyInfo;
import org.opensc.pkcs15.asn1.proxy.Directory;
import org.opensc.pkcs15.asn1.proxy.StreamResolver;
import org.opensc.pkcs15.asn1.proxy.StreamResolverDirectory;
import org.opensc.pkcs15.asn1.ref.Path;

/**
 * This implementation of a PKCS#15 context resolves token files an the ASN.1
 * stream located in EFs therein.
 * 
 * @author wglas
 */
public class TokenContext implements Context {
    
    private final Token token;
    private final TokenStreamResolver streamResolver;
    
    private class TokenStreamResolver implements StreamResolver<Path>
    {
        @Override
        public InputStream readReference(Path ref) throws IOException {
          
            PathHelper.selectEF(TokenContext.this.token,new TokenPath(ref.getPath()));
            
            InputStream is = TokenContext.this.token.readEFData();
            
            if (ref.getIndex() == null || ref.getLength() == null)
                return is;
                
            byte [] ba = new byte[ref.getLength().intValue()];
            
            is.skip(ref.getIndex().intValue());
            int n = is.read(ba);
            
            return new ByteArrayInputStream(ba,0,n);
        }

        @Override
        public OutputStream writeReference(Path ref) throws IOException {
            
            PathHelper.selectEF(TokenContext.this.token,new TokenPath(ref.getPath()));
            
            OutputStream os = TokenContext.this.token.writeEFData();
            
            if (ref.getIndex() == null || ref.getLength() == null)
                return os;
           
            throw new UnsupportedOperationException("Writing to a sub-stream is not yet implemented.");
        }
        
    }
    
    public TokenContext(Token token) {
        this.token = token;
        this.streamResolver = new TokenStreamResolver();
    }
    
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.Context#getPathResolver()
     */
    @Override
    public StreamResolver<Path> getPathResolver() {
        return this.streamResolver;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.Context#getRSAKeyInfoDirectory()
     */
    @Override
    public Directory<DERInteger, NullKeyInfo> getNullKeyInfoDirectory() {
        
        return null;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.Context#getRSAPrivateKeyDirectory()
     */
    @Override
    public Directory<Path, RSAPrivateKeyObject> getRSAPrivateKeyDirectory() {
        
        return new StreamResolverDirectory<Path, RSAPrivateKeyObject>(this.streamResolver,RSAKeyInfoFactory.class);
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.Context#getRSAPublicKeyDirectory()
     */
    @Override
    public Directory<Path, RSAPublicKeyObject> getRSAPublicKeyDirectory() {
        
        return new StreamResolverDirectory<Path, RSAPublicKeyObject>(this.streamResolver,RSAPublicKeyChoice.class);
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.Context#getX509CertificateDirectory()
     */
    @Override
    public Directory<Path, X509CertificateObject> getX509CertificateDirectory() {
        
        return new StreamResolverDirectory<Path, X509CertificateObject>(this.streamResolver,X509CertificateObjectImpl.class);
    }

    /**
     * @return the token
     */
    public Token getToken() {
        return this.token;
    }

}
