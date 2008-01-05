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

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <PRE>
 * DDO ::= SEQUENCE {
 *         oid                OBJECT IDENTIFIER,
 *         odfPath            Path OPTIONAL,
 *         tokenInfoPath [0] Path OPTIONAL,
 *         unusedPath         [1] Path OPTIONAL,
 *         ... -- For future extensions
 *         }
 * </PRE>
 * 
 * @author wglas
 */
public class DDO extends ASN1Encodable {

    private String oid;
    private Path odfPath;
    private Path tokenInfoPath;
    private Path unusedPath;
    
    /**
     * Default constructor.
     */
    public DDO() {
        super();
    }

    /**
     * @param obj The ASN.1 object to decode.
     * @return A DDO instance.
     */
    public static DDO getInstance (Object obj)
    {
        if (obj instanceof DDO)
            return (DDO)obj;
            
        if (obj instanceof ASN1Sequence)
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
        
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing oid member in DDO ASN.1 SEQUENCE.");
            
            DDO ret = new DDO();
            
            Object o = objs.nextElement();
            
            ret.setOid(DERObjectIdentifier.getInstance(o).getId());
            
            if (!objs.hasMoreElements()) return ret;
            
            o = objs.nextElement();
            
            if (o instanceof ASN1Sequence)
            {
                ret.setOdfPath(Path.getInstance(o));
                if (!objs.hasMoreElements()) return ret;
                
                o = objs.nextElement();                
            }
            
            ASN1TaggedObject to = ASN1TaggedObject.getInstance(o);
            
            if (to.getTagNo() == 0)
            {
                ret.setTokenInfoPath(Path.getInstance(to.getObject()));
                
                if (!objs.hasMoreElements()) return ret;
                
                o = objs.nextElement();                
                to = ASN1TaggedObject.getInstance(o);
            }
            
            if (to.getTagNo() == 1)
            {
                ret.setUnusedPath(Path.getInstance(to.getObject()));
            }
            else
                throw new IllegalArgumentException("Invalid member tag ["+to.getTagNo()+"] in DDO ASN.1 SEQUENCE.");
            
            return ret;
        }
        
        throw new IllegalArgumentException("DDO must be encoded as an ASN.1 SEQUENCE.");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v= new ASN1EncodableVector();
        
        if (this.oid != null)
            v.add(new DERObjectIdentifier(this.oid));
        
        if (this.odfPath != null)
            v.add(this.odfPath);
            
        if (this.tokenInfoPath != null)
            v.add(new DERTaggedObject(0,this.tokenInfoPath));
        
        if (this.unusedPath != null)
            v.add(new DERTaggedObject(1,this.unusedPath));
            
        return new DERSequence(v);
    }

    /**
     * @return the oid
     */
    public String getOid() {
        return this.oid;
    }

    /**
     * @param oid the oid to set
     */
    public void setOid(String oid) {
        this.oid = oid;
    }

    /**
     * @return the odfPath
     */
    public Path getOdfPath() {
        return this.odfPath;
    }

    /**
     * @param odfPath the odfPath to set
     */
    public void setOdfPath(Path odfPath) {
        this.odfPath = odfPath;
    }

    /**
     * @return the tokenInfoPath
     */
    public Path getTokenInfoPath() {
        return this.tokenInfoPath;
    }

    /**
     * @param tokenInfoPath the tokenInfoPath to set
     */
    public void setTokenInfoPath(Path tokenInfoPath) {
        this.tokenInfoPath = tokenInfoPath;
    }

    /**
     * @return the unusedPath
     */
    public Path getUnusedPath() {
        return this.unusedPath;
    }

    /**
     * @param unusedPath the unusedPath to set
     */
    public void setUnusedPath(Path unusedPath) {
        this.unusedPath = unusedPath;
    }

}
