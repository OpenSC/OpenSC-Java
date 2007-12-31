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
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;

/**
 * This class decode/encodes a SEQUENCE OF.
 * 
 * @author wglas
 */
public class SequenceOfFactory<EntityType extends DEREncodable> {

    private final InstanceFactory<EntityType> instanceFactory;
    
    /**
     * @param clazz The ASN.1 class which is instantiated. Note,
     *              that this might be the class of an actual implementation,
     *              if EntityType is an interface.
     */
    public SequenceOfFactory(Class<? extends EntityType> clazz) {
        this.instanceFactory = new InstanceFactory<EntityType>(clazz);
    }
    
    /**
     * @param obj The ASN.1 object to decode.
     * @return A decoded SequenceOf instance.
     */
    public SequenceOf<EntityType> getInstance(Object obj) {
        
        if (obj instanceof SequenceOf) {
            return (SequenceOf<EntityType>)obj;
        }
    
        if (obj instanceof ASN1Sequence) {
            
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            SequenceOf<EntityType> ret = new SequenceOfImpl<EntityType>();

            while (objs.hasMoreElements()) {
                
                Object o = objs.nextElement();
                
                ret.addEntity(this.instanceFactory.getInstance(o));
            }
            
            return ret;
        }
        
        throw new IllegalArgumentException("SequenceOf{"+this.instanceFactory.getClazz().getSimpleName()+"} must be encoded as an ASN.1 SEQUENCE.");
    }
    
    
    /**
     * @param is The InputStream to read from.
     * @return The SequenceOf instance, which is the concatenation of all objects in
     *         the given InputStream.
     * @throws IOException
     */
    public SequenceOf<EntityType> readInstance(InputStream is) throws IOException {
        
        ASN1InputStream ais = new ASN1InputStream(is);
        
        DERObject obj;
        SequenceOf<EntityType> ret = new SequenceOfImpl<EntityType>();
        
        while ((obj = ais.readObject()) != null)
        {
            // The internal END_OF_STREAM object of
            // ASN1InputStream does not derive from ASN1Object, while
            // all other meaningful DERObjects do, so leave the loop
            // if this is not an ASN1Object
            if (!(obj instanceof ASN1Object))
                break;
            
            ret.addEntity(this.instanceFactory.getInstance(obj));
        }
        return ret;
    }
        
    /**
     * Write all elements of the supplied SequenceOf to the given OutputStream. 
     * 
     * @param os The OutputStream to write to. The stream is closed by this
     *           function after writing all members of <code>seq</code>.
     * @param seq The sequence to write.
     * @throws IOException
     */
    public void writeInstance(OutputStream os, SequenceOf<EntityType> seq) throws IOException {
        
        ASN1OutputStream aos = new ASN1OutputStream(os);
        
        List<EntityType> sequence = seq.getSequence();
        
        if (sequence != null) {
            
            for (EntityType e : sequence) {
             
                aos.writeObject(e);
            }
        }
        
        // write END_OF_STREAM
        aos.write(0);
        aos.write(0);
        aos.close();
    }

    /**
     * @return the instanceFactory
     */
    public InstanceFactory<EntityType> getInstanceFactory() {
        return this.instanceFactory;
    }
   
}
