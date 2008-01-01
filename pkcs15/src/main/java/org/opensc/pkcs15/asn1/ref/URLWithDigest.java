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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.DigestInfo;

/**
 * <PRE>
 * URLWithDigest ::= [3] SEQUENCE {
 *             url         IA5String,
 *             digest      DigestInfoWithDefault
 *             }
 *         }
 * </PRE>
 * 
 * @author wglas
 */
public class URLWithDigest extends URL {

    private DigestInfo digest;
    
    /**
     * Default constructor.
     */
    public URLWithDigest() {
        super();
    }

    /**
     * @param url
     * @param digest
     */
    public URLWithDigest(String url,DigestInfo digest) {
        super();
        this.setUrl(url);
        this.digest = digest;
    }
    
    /**
     * @param obj  The ASN.1 object to decode.
     * @return true, if this object can be decoded to an URLWithDigest.
     */
    public static boolean canGetInstance (Object obj)
    {
        if (obj instanceof URLWithDigest) return true;
        
        if (obj instanceof ASN1TaggedObject) {
            ASN1TaggedObject to = (ASN1TaggedObject)obj;
            return  to.getTagNo() == 3;
        }
        
        return false;
    }

    /**
     * @param obj The ASN.1 object to decode.
     * @return An URLWithDigest instance.
     */
    public static URLWithDigest getInstance (Object obj)
    {
        if (obj instanceof URLWithDigest)
            return (URLWithDigest)obj;
            
        if (obj instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject to = (ASN1TaggedObject)obj;
            
            if (to.getTagNo()!=3)
                throw new IllegalArgumentException("Invalid tag ["+to.getTagNo()+"] in URL.");
 
            ASN1Sequence seq = ASN1Sequence.getInstance(to.getDERObject());
            
            Enumeration<Object> objs = seq.getObjects();
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing url member in URLWithDigest SEQUENCE.");
            
            DERIA5String url = DERIA5String.getInstance(objs.nextElement());
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing digest member in URLWithDigest SEQUENCE.");
            
            DigestInfo digest = DigestInfo.getInstance(objs.nextElement());
            
            return new URLWithDigest(url.getString(),digest);
        }
        
        throw new IllegalArgumentException("AccessControlRule must be encoded as an ASN.1 tagged object.");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERIA5String(this.getUrl(),true));
        v.add(this.digest);

        return new DERTaggedObject(3,new DERSequence(v));
    }

    /**
     * @param url the url to set
     */
    public void setUrl(String url) {
        if (!DERIA5String.isIA5String(url))
            throw new IllegalArgumentException("url ["+url+"] is not an ASN.1 IA5String.");
         super.setUrl(url);
    }

    /**
     * @return the digest
     */
    public DigestInfo getDigest() {
        return this.digest;
    }

    /**
     * @param digest the digest to set
     */
    public void setDigest(DigestInfo digest) {
        this.digest = digest;
    }

}
