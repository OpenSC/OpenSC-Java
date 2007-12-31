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

package org.opensc.pkcs15.asn1;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;

/**
 * This StreamResolver resolves URLs.
 * 
 * @author wglas
 */
public class URLStreamResolver
implements StreamResolver<URL> {

    /**
     * Default constructor.
     */
    public URLStreamResolver() {
    }
    
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.StreamResolver#readReference(org.bouncycastle.asn1.DEREncodable)
     */
    @Override
    public InputStream readReference(URL ref) {
        try {
            java.net.URL jURL = new java.net.URL(ref.getUrl());
            return jURL.openStream();
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("URL ["+ref.getUrl()+"] is malformed.",e);
        } catch (IOException e) {
            throw new IllegalArgumentException("URL ["+ref.getUrl()+"] cannot be opened.",e);
        }
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.StreamResolver#writeReference(org.bouncycastle.asn1.DEREncodable)
     */
    @Override
    public OutputStream writeReference(URL ref) {
        java.net.URL jURL;
        
        try {
            jURL = new java.net.URL(ref.getUrl());
            return jURL.openConnection().getOutputStream();
            
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("URL ["+ref.getUrl()+"] is malformed.",e);
        } catch (IOException e) {
            throw new IllegalArgumentException("URL ["+ref.getUrl()+"] cannot be opened.",e);
        }
    }
}
