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

package org.opensc.pkcs15.asn1.ref;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.opensc.pkcs15.asn1.proxy.Directory;
import org.opensc.pkcs15.asn1.proxy.ReferenceProxyFactory;
import org.opensc.pkcs15.asn1.proxy.StreamResolver;
import org.opensc.pkcs15.asn1.sequence.SequenceOf;
import org.opensc.pkcs15.asn1.sequence.SequenceOfFactory;
import org.opensc.pkcs15.asn1.sequence.SequenceOfStreamResolverDirectory;

/**
 * Decode the ASN.1 <code>PathOrObjects{Type}</code> choice.
 * 
 * <PRE>
 * PathOrObjects {ObjectType} ::= CHOICE {
 *        path      Path,
 *        objects [0] SEQUENCE OF ObjectType,
 *        ...,
 *        indirect-protected [1] ReferencedValue {EnvelopedData {SEQUENCE OF ObjectType}},
 *        direct-protected [2] EnvelopedData {SEQUENCE OF ObjectType},
 *        }
 * </PRE>
 * 
 * @author wglas
 */
public class PathOrObjectsFactory<EntityType extends DEREncodable> {
    
    private final SequenceOfFactory<EntityType> sequenceOfFactory;
    @SuppressWarnings("unchecked")
    private final ReferenceProxyFactory<Path,SequenceOf> pathProxyFactory;
    private final String entityName;

    /**
     * Construct a factory for ASN.1 ObjectValues.
     * 
     * @param clazz The class of the EntityType interface, which is implemented by direct
     *              objects and proxies to indirect references.  
     * @param implClazz The class of the implementation of interface, which is instantiated
     *              by direct objects.  
     */
    @SuppressWarnings("unchecked")
    public PathOrObjectsFactory(Class<EntityType> clazz, Class<? extends EntityType> implClazz)
    {
        this.sequenceOfFactory = new SequenceOfFactory<EntityType>(implClazz);
        this.pathProxyFactory = new ReferenceProxyFactory<Path,SequenceOf>(SequenceOf.class);
        this.entityName = this.pathProxyFactory.getEntityInterface().getSimpleName();
    }
    
    /**
     * @param obj An ASN.1 object to resolve.
     * @param pathResolver The stream resolver used to resolve path references.
     * @return An instance or a proxy depending on the type of the ReferencedValue. 
     */
    @SuppressWarnings("unchecked")
    public SequenceOf<EntityType> getInstance(Object obj,
            StreamResolver<Path> pathResolver) {
        
        if (obj instanceof SequenceOf)
            return (SequenceOf<EntityType>) obj;
        
        // ReferencedValue
        
        // Choice 1: indirect / Path 
        if (obj instanceof ASN1Sequence) {
            return this.pathProxyFactory.getProxy(Path.getInstance(obj),
            (Directory<Path, SequenceOf>)
            new SequenceOfStreamResolverDirectory<Path,EntityType>(pathResolver,this.sequenceOfFactory));
            
        }
        
        if (obj instanceof ASN1TaggedObject) {
            
            ASN1TaggedObject to = ASN1TaggedObject.getInstance(obj);

            switch(to.getTagNo()) {
            
            case 0:
                // Choice 3: direct
                return this.sequenceOfFactory.getInstance(to.getDERObject());
                
            case 1:
                // Choice 4: indirect-protected
                throw new IllegalArgumentException("PathOrObjects{"+this.entityName+"}.indirect-protected CHOICE is not implemented.");
                
            case 2:
                // Choice 5: direct-protected
                throw new IllegalArgumentException("PathOrObjects{"+this.entityName+"}.direct-protected CHOICE is not implemented.");         
            
            default:
                throw new IllegalArgumentException("Invalid PathOrObjects{"+this.entityName+"} member tag ["+to.getTagNo()+"].");
            }
       }
       
        throw new IllegalArgumentException("PathOrObjects{"+this.entityName+"} must be encoded as an ASN.1 SEQUENCE or ASN.1 tagged object.");
    }
}
