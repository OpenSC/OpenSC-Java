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
import java.net.MalformedURLException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEREncodable;

/**
 * This directory resolves URLs.
 * 
 * @author wglas
 */
public class URLDirectory<EntityType extends DEREncodable>
implements Directory<URL,EntityType> {

    private final InstanceFactory<EntityType> instanceFactory;
    
    /**
     * @param clazz The ASN.1 class which is instantiated. Note,
     *              that this might be the class of an actual implementation,
     *              if EntityType is an interface.
     */
    public URLDirectory(Class<? extends EntityType> clazz) {
        this.instanceFactory = new InstanceFactory<EntityType>(clazz);
    }
    
    /**
     * @param instanceFactory The factory for ASN.1 instances.
     */
    public URLDirectory(InstanceFactory<EntityType> instanceFactory) {
        this.instanceFactory = instanceFactory;
    }
    
   /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.Directory#resolveReference(org.bouncycastle.asn1.DEREncodable, org.bouncycastle.asn1.DEREncodable)
     */
    @Override
    public EntityType resolveReference(URL url, EntityType t) {
        
        java.net.URL jURL;
        
        try {
            jURL = new java.net.URL(url.getUrl());
            ASN1InputStream ais = new ASN1InputStream(jURL.openStream());
            
            return this.instanceFactory.getInstance(ais.readObject());
            
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("URL ["+url.getUrl()+"] is malformed.",e);
        } catch (IOException e) {
            throw new IllegalArgumentException("URL ["+url.getUrl()+"] cannot be opened.",e);
        }
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.Directory#registerEntity(org.bouncycastle.asn1.DEREncodable)
     */
    @Override
    public URL registerEntity(EntityType entity) {
        
        throw new UnsupportedOperationException("Entities can not be registered in an URL directory.");
    }

    /**
     * @return the instanceFactory
     */
    public InstanceFactory<EntityType> getInstanceFactory() {
        return this.instanceFactory;
    } 
}
