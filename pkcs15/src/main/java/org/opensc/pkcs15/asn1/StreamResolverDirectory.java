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

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DEREncodable;

/**
 * An adapter for using a StreamResolver as a Directory.
 * 
 * @author wglas
 */
public class StreamResolverDirectory<ReferenceType extends DEREncodable, EntityType extends DEREncodable> implements Directory<ReferenceType, EntityType> {

    private final StreamResolver<ReferenceType> streamResolver;
    private final InstanceFactory<EntityType> instanceFactory;
    
    public StreamResolverDirectory(StreamResolver<ReferenceType> streamResolver,
            Class<? extends EntityType> clazz) {
        
        this.streamResolver = streamResolver;
        this.instanceFactory = new InstanceFactory<EntityType>(clazz);
    }

    public StreamResolverDirectory(StreamResolver<ReferenceType> streamResolver,
            InstanceFactory<EntityType> instanceFactory) {
        
        this.streamResolver = streamResolver;
        this.instanceFactory = instanceFactory;
    }

   /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.Directory#resolveReference(org.bouncycastle.asn1.DEREncodable, org.bouncycastle.asn1.DEREncodable)
     */
    @Override
    public EntityType resolveReference(ReferenceType ref, EntityType t) {
       
        try {
            
            ASN1InputStream ais = new ASN1InputStream(this.streamResolver.readReference(ref));
            
            return this.instanceFactory.getInstance(ais.readObject());
            
        } catch (IOException e) {
            throw new IllegalArgumentException("Reference ["+ref+"] cannot be read.",e);
        }
    }
    
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.Directory#updateEntity(org.bouncycastle.asn1.DEREncodable, org.bouncycastle.asn1.DEREncodable)
     */
    @Override
    public void updateEntity(ReferenceType ref, EntityType entity) {
        
        try {
            ASN1OutputStream aos = new ASN1OutputStream(this.streamResolver.writeReference(ref));
        
            aos.writeObject(entity);
            aos.close();

        } catch (IOException e) {
            throw new IllegalArgumentException("Reference ["+ref+"] cannot be written.",e);
        }
    }
    
    /**
     * @return the streamResolver
     */
    public StreamResolver<ReferenceType> getStreamResolver() {
        return this.streamResolver;
    }

    /**
     * @return the instanceFactory
     */
    public InstanceFactory<EntityType> getInstanceFactory() {
        return this.instanceFactory;
    }
}
