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

import org.bouncycastle.asn1.DEREncodable;

/**
 * An adapter for using a StreamResolver as a Directory for sequences.
 * 
 * @author wglas
 */
public class SequenceOfStreamResolverDirectory<ReferenceType extends DEREncodable, EntityType extends DEREncodable>
implements Directory<ReferenceType, SequenceOf<EntityType>> {

    private final StreamResolver<ReferenceType> streamResolver;
    private final SequenceOfFactory<EntityType> sequenceOfFactory;
    
    public SequenceOfStreamResolverDirectory(StreamResolver<ReferenceType> streamResolver,
            Class<? extends EntityType> clazz) {
        
        this.streamResolver = streamResolver;
        this.sequenceOfFactory = new SequenceOfFactory<EntityType>(clazz);
    }

    public SequenceOfStreamResolverDirectory(StreamResolver<ReferenceType> streamResolver,
            SequenceOfFactory<EntityType> sequenceOfFactory) {
        
        this.streamResolver = streamResolver;
        this.sequenceOfFactory = sequenceOfFactory;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.Directory#resolveReference(org.bouncycastle.asn1.DEREncodable, org.bouncycastle.asn1.DEREncodable)
     */
    @Override
    public SequenceOf<EntityType> resolveReference(ReferenceType ref) {
       
        try {
            
            InputStream is = this.streamResolver.readReference(ref);
            
            return this.sequenceOfFactory.readInstance(is);
            
        } catch (IOException e) {
            throw new IllegalArgumentException("Reference ["+ref+"] cannot be read.",e);
        }
    }
    
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.asn1.Directory#updateEntity(org.bouncycastle.asn1.DEREncodable, org.bouncycastle.asn1.DEREncodable)
     */
    @Override
    public void updateEntity(ReferenceType ref, SequenceOf<EntityType> entity) {
        
        try {
            OutputStream os = this.streamResolver.writeReference(ref);
        
            this.sequenceOfFactory.writeInstance(os,entity);

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
     * @return the sequenceOfFactory
     */
    public SequenceOfFactory<EntityType> getSequenceOfFactory() {
        return this.sequenceOfFactory;
    }

}
