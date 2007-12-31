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

package org.opensc.pkcs15.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERPrintableString;

/**
 * <PRE>
 * URL ::= CHOICE {
 *         url       PrintableString,
 *         urlWithDigest [3] SEQUENCE {
 *             url         IA5String,
 *             digest      DigestInfoWithDefault
 *             }
 *         }
 * </PRE>
 * 
 * @author wglas
 */
public class URL extends ASN1Encodable {

    private String url;
    
    /**
     * Default constructor.
     */
    public URL() {
        super();
    }

    /**
     * @param url
     * @param digest
     */
    public URL(String url) {
        super();
        this.url = url;
    }
    
    /**
     * @param obj  The ASN.1 object to decode.
     * @return true, if this object can be decoded to an URL.
     */
    public static boolean canGetInstance (Object obj)
    {
        if (obj instanceof URL) return true;
        if (obj instanceof DERIA5String) return true;
        if (obj instanceof DERPrintableString) return true;
        return URLWithDigest.canGetInstance(obj);
    }

    
    /**
     * @param obj The ASN.1 object to decode.
     * @return An URLWithDigest instance.
     */
    public static URL getInstance (Object obj)
    {
        if (obj instanceof URL)
            return (URL)obj;
            
        if (obj instanceof DERIA5String)
        {
            return new URL(DERIA5String.getInstance(obj).getString());
        }
            
        if (obj instanceof DERPrintableString)
        {
            return new URL(DERPrintableString.getInstance(obj).getString());
        }
            
        if (obj instanceof ASN1TaggedObject)
        {
            return URLWithDigest.getInstance(obj);
        }
        
        throw new IllegalArgumentException("URL must be encoded as an ASN.1 IA5String, PrintableString or [3]URLWithDigest.");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        if (DERIA5String.isIA5String(this.url))
            return new DERIA5String(this.url);
        
        return new DERPrintableString(this.url);
    }

    /**
     * @return the url
     */
    public String getUrl() {
        return this.url;
    }

    /**
     * @param url the url to set
     */
    public void setUrl(String url) {
         this.url = url;
    }

}
