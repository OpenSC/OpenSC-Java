/***********************************************************
 * $Id$
 * 
 * PKCS#15 cryptographic provider of the opensc project.
 * http://www.opensc-project.org
 *
 * Created: 25.12.2007
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
 ***********************************************************/

package org.opensc.pkcs15.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERTags;

/**
 * An entry in an ISO7816 application directory. in the following format:
 * 
 *  <PRE>
 *  DIRRecord ::= [APPLICATION 1] SEQUENCE {
 *     aid       [APPLICATION 15] OCTET STRING,
 *     label     [APPLICATION 16] UTF8String OPTIONAL,
 *     path      [APPLICATION 17] OCTET STRING,
 *     ddo       [APPLICATION 19] DDO OPTIONAL
 *  }
 *  </PRE>
 *
 * @author wglas
 */
public class ISO7816ApplicationTemplate extends ASN1Encodable {

    public static final int AID_TAG_NO = 15;
    public static final int APPLICATION_DESCRIPTION_TAG_NO = 16;
    public static final int PATH_TAG_NO = 17;
    public static final int DISCRETIONARY_DATA_TAG_NO = 51;
    
    private static final Charset utf8Encoding = Charset.forName("UTF-8");
    
    private byte[] aid;
    private String description;
    private byte[] path;
    private byte[] discretionaryData;
    
    /**
     * Default contructor.
     */
    public ISO7816ApplicationTemplate() {
    }
    
    /**
     * @param o An ASN.1 sequence.
     */
    public ISO7816ApplicationTemplate(DERApplicationSpecific o) {
        
        ASN1InputStream ais = new ASN1InputStream(o.getContents());
        
        DERObject obj;

        try {
            while ((obj = ais.readObject()) != null)
            {
                if (!(obj instanceof DERApplicationSpecific))
                    throw new IllegalArgumentException("Item of an application template is not an application specific ASN1 object.");
                    
                DERApplicationSpecific to = (DERApplicationSpecific)obj;
                
                switch (to.getApplicationTag())
                {
                case AID_TAG_NO:
                    this.aid = to.getContents();
                    break;
                case APPLICATION_DESCRIPTION_TAG_NO:
                    this.description = new String(to.getContents(),utf8Encoding);
                    break;
                case PATH_TAG_NO:
                    this.path = to.getContents();
                    break;
                case DISCRETIONARY_DATA_TAG_NO:
                    this.discretionaryData = to.getContents();
                    break;
                  
                }
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("I/O error parsing ASN1 object.",e);
        }
    }

    /**
     * @param o An ASN.1 sequence or an instance of ISO7816ApplicationTemplate.
     * @return An instance of ISO7816ApplicationTemplate.
     * @throws IllegalArgumentException If the passed object is of the wrong type.
     */
    public static ISO7816ApplicationTemplate getInstance(Object  o)
    throws IllegalArgumentException
    {
        if (o == null || o instanceof ISO7816ApplicationTemplate)
        {
            return (ISO7816ApplicationTemplate)o;
        }
        else if (o instanceof DERApplicationSpecific)
        {
            DERApplicationSpecific as = (DERApplicationSpecific)o;
            if (as.getApplicationTag() != 1)
                throw new IllegalArgumentException("Invalid application tag ["+as.getApplicationTag()+"].");
                
            return new ISO7816ApplicationTemplate((DERApplicationSpecific)o);
        }
        else
            return null;
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        
        ASN1OutputStream aos = new ASN1OutputStream(bos);
        try {
            
            if (this.aid != null)
                aos.writeObject(new DERApplicationSpecific(AID_TAG_NO,this.aid));
                        
            if (this.description != null)
                aos.writeObject(new DERApplicationSpecific(APPLICATION_DESCRIPTION_TAG_NO,this.description.getBytes("utf-8")));
            
            if (this.path != null)
                aos.writeObject(new DERApplicationSpecific(PATH_TAG_NO,this.path));
            
            if (this.discretionaryData != null)
                aos.writeObject(new DERApplicationSpecific(DISCRETIONARY_DATA_TAG_NO,this.discretionaryData));
            
            return new DERApplicationSpecific(1 | DERTags.CONSTRUCTED,bos.toByteArray());
        
        } catch(IOException e)
        {
            throw new RuntimeException("IO error contructions ASN1 representation.",e);
        }
    }

    /**
     * @return The application ID.
     */
    public byte[] getAid() {
        return this.aid;
    }

    /**
     * @param aid the aid to set
     */
    public void setAid(byte[] aid) {
        this.aid = aid;
    }

    /**
     * @return The application description.
     */
    public String getDescription() {
        return this.description;
    }

    /**
     * @param description the description to set
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * @return The path to the application on the token.
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
     * @return The application specific discretionary data.
     */
    public byte[] getDiscretionaryData() {
        return this.discretionaryData;
    }

    /**
     * @param discretionaryData the discretionaryData to set
     */
    public void setDiscretionaryData(byte[] discretionaryData) {
        this.discretionaryData = discretionaryData;
    }

}
