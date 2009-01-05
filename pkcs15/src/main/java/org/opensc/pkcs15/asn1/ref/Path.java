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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.opensc.pkcs15.asn1.helper.IntegerHelper;
import org.opensc.pkcs15.util.Util;

/**
 * <PRE>
 * Path ::= SEQUENCE {
 *        path     OCTET STRING,
 *        index    INTEGER (0..pkcs15-ub-index) OPTIONAL,
 *        length [0] INTEGER (0..pkcs15-ub-index) OPTIONAL
 *        }
 *        ( WITH COMPONENTS {..., index PRESENT, length PRESENT}|
 *          WITH COMPONENTS {..., index ABSENT, length ABSENT}    )
 * </PRE>
 * 
 * @author wglas
 */
public class Path extends ASN1Encodable {

    private byte [] path;
    private Integer index;
    private Integer length;
    
    /**
     * Default constructor.
     */
    public Path() {
    }
    
    /**
     * @param obj The ASN.1 object to decode-
     * @return The decoded Path instance.
     */
    public static Path getInstance(Object obj) {
        
        if (obj instanceof Path) {
            return (Path) obj;
        }
        
        if (!(obj instanceof ASN1Sequence))
            throw new IllegalArgumentException("PKCS#15 path' must be encoded as ASN.1 SEQUENCE.");
        
        ASN1Sequence seq = (ASN1Sequence)obj;
        Path ret = new Path();
        
        Enumeration<Object> objs = seq.getObjects();
        
        if (!objs.hasMoreElements())
            throw new IllegalArgumentException("Missing path member in PKCS#15 path object.");
            
        ret.setPath(ASN1OctetString.getInstance(objs.nextElement()).getOctets());
        
        if (objs.hasMoreElements())
        {
            ret.setIndex(IntegerHelper.toInteger(DERInteger.getInstance(objs.nextElement()).getValue()));
            
            if (!objs.hasMoreElements())
                throw new IllegalArgumentException("Missing length member after index in PKCS#15 path object.");
            
            ASN1TaggedObject to = ASN1TaggedObject.getInstance(objs.nextElement());
                
            if (to.getTagNo() != 0)
                throw new IllegalArgumentException("Illegal tag ["+to.getTagNo()+"] for length member in PKCS#15 path object.");
            
            ret.setLength(IntegerHelper.toInteger(DERInteger.getInstance(to.getObject()).getValue()));
        }
        
        return ret;
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DEROctetString(this.path));
        if (this.index != null)
            v.add(new DERInteger(this.index.intValue()));
        if (this.length != null)
            v.add(new DERTaggedObject(0,new DERInteger(this.length.intValue())));

        return new DERSequence(v);
   }

    /**
     * @return the path
     */
    public byte[] getPath() {
        return this.path;
    }

    /**
     * @param path the path to set
     */
    public void setPath(byte[] path) {
        this.path = path;
    }

    /**
     * @return the index
     */
    public Integer getIndex() {
        return this.index;
    }

    /**
     * @param index the index to set
     */
    public void setIndex(Integer index) {
        this.index = index;
    }

    /**
     * @return the length
     */
    public Integer getLength() {
        return this.length;
    }

    /**
     * @param length the length to set
     */
    public void setLength(Integer length) {
        this.length = length;
    }

    public String toString() {
        
        StringBuffer sb = new StringBuffer();
        
        sb.append("Path[");
        
        int i=0;
        
        while (i < this.path.length) {
            
            if (i>0) sb.append('/');
            Util.appendHexByte(sb,this.path[i]);
            ++i;
            if (i >= this.path.length) break;
            Util.appendHexByte(sb,this.path[i]);
            ++i;
        }
        
        if (this.index != null && this.length !=null) {
            sb.append("(");
            sb.append(this.index);
            sb.append(",");
            sb.append(this.length);
            sb.append(")]");
        }
        else     
            sb.append("]");
        
        return sb.toString();
    }
}
