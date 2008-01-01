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
 * Created: 01.01.2008
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.opensc.pkcs15.asn1.ref.PathOrObjectsFactory;
import org.opensc.pkcs15.asn1.sequence.SequenceOf;
import org.opensc.pkcs15.asn1.sequence.SequenceOfFactory;

/**
 * This is the ASN.1 mapping of the EF(ODF) file, which serves as
 * a root object for all PKCS#15 toplevel objects.
 * 
 * <PRE>
 * PKCS15Objects ::= CHOICE {
 *       privateKeys             [0] PrivateKeys,
 *       publicKeys              [1] PublicKeys,
 *       trustedPublicKeys [2] PublicKeys,
 *       secretKeys              [3] SecretKeys,
 *       certificates            [4] Certificates,
 *       trustedCertificates [5] Certificates,
 *       usefulCertificates      [6] Certificates,
 *       dataObjects             [7] DataObjects,
 *       authObjects             [8] AuthObjects,
 *       ... -- For future extensions
 *       }
 * </PRE>
 * 
 * @author wglas
 */
public class PKCS15Objects {

    private static final PathOrObjectsFactory<PKCS15PrivateKey> privateKeysFactory =
        new PathOrObjectsFactory<PKCS15PrivateKey>(PKCS15PrivateKey.class);

    private static final PathOrObjectsFactory<PKCS15PublicKey> publicKeysFactory =
        new PathOrObjectsFactory<PKCS15PublicKey>(PKCS15PublicKey.class);

    private static final PathOrObjectsFactory<PKCS15Certificate> certificatesFactory =
        new PathOrObjectsFactory<PKCS15Certificate>(PKCS15Certificate.class);

    private static final PathOrObjectsFactory<PKCS15AuthenticationObject> authObjectsFactory =
        new PathOrObjectsFactory<PKCS15AuthenticationObject>(PKCS15AuthenticationObject.class);
    
    private SequenceOf<PKCS15PrivateKey> privateKeys;
    private SequenceOf<PKCS15PublicKey> publicKeys;
    private SequenceOf<PKCS15PublicKey> trustedPublicKeys;
    private SequenceOf<PKCS15Certificate> certificates;
    private SequenceOf<PKCS15Certificate> trustedCertificates;
    private SequenceOf<PKCS15Certificate> usefulCertificates;
    private SequenceOf<PKCS15AuthenticationObject> authObjects;
    
    /**
     * Default constructor.
     */
    public PKCS15Objects() {
    }
    
    /**
     * Parse a PKCS15Objects instance from an input stream.
     * The stream is closed after reading all members.
     * 
     * @param is The InputStream to read from.
     * @param context The context used for proxy instantiation.
     * @return A PKCS15Objects instance.
     * @throws IOException upon read errors.
     */
    public static PKCS15Objects readInstance(InputStream is, Context context) throws IOException
    {
        ContextHolder.setContext(context);
        
        try
        {
            ASN1InputStream ais = new ASN1InputStream(is);
        
            PKCS15Objects ret = new PKCS15Objects();
        
            DERObject obj;
        
            while ((obj = ais.readObject()) != null)
            {
                // The internal END_OF_STREAM object of
                // ASN1InputStream does not derive from ASN1Object, while
                // all other meaningful DERObjects do, so leave the loop
                // if this is not an ASN1Object
                if (!(obj instanceof ASN1Object))
                    break;

                if (!(obj instanceof ASN1TaggedObject))
                    throw new IllegalArgumentException("PKCS15Objects must consist of a sequence of ASN.1 TAGGED OBJECTS.");
            
                ASN1TaggedObject to = (ASN1TaggedObject)obj;

                switch (to.getTagNo())
                {
                case 0:
                    ret.setPrivateKeys(privateKeysFactory.getInstance(to.getDERObject()));
                    break;
                case 1:
                    ret.setPublicKeys(publicKeysFactory.getInstance(to.getDERObject()));
                    break;
                case 2:
                    ret.setTrustedPublicKeys(publicKeysFactory.getInstance(to.getDERObject()));
                    break;
                case 3:
                    throw new IllegalArgumentException("SecretKeys are not supported yet.");
                case 4:
                    ret.setCertificates(certificatesFactory.getInstance(to.getDERObject()));
                    break;
                case 5:
                    ret.setTrustedCertificates(certificatesFactory.getInstance(to.getDERObject()));
                    break;
                case 6:
                    ret.setUsefulCertificates(certificatesFactory.getInstance(to.getDERObject()));
                    break;
                case 7:
                    throw new IllegalArgumentException("DataObjects are not supported yet.");
                case 8:
                    ret.setAuthObjects(authObjectsFactory.getInstance(to.getDERObject()));
                    break;
                    
                default:
                    throw new IllegalArgumentException("Invalid memebr tag ["+to.getTagNo()+"] in PKCS15Objects sequence.");
               }
            }
            
            ais.close();
            return ret;
            
        } finally {
            ContextHolder.removeContext();
        }
        
    }
    
    /**
     * Write this instance to an OuputStream. The stream is closed after
     * writing all members.
     * 
     * @param os The stream to write to.
     * @throws IOException Upon write errors.
     */
    public void writeInstance(OutputStream os) throws IOException {
        
        ASN1OutputStream aos = new ASN1OutputStream(os);
        
        if (this.privateKeys != null)
            aos.writeObject(new DERTaggedObject(0,this.privateKeys));
        
        if (this.publicKeys != null)
            aos.writeObject(new DERTaggedObject(1,this.publicKeys));
        
        if (this.trustedPublicKeys != null)
            aos.writeObject(new DERTaggedObject(2,this.trustedPublicKeys));
        
        // secret keys to come...
        
        if (this.certificates != null)
            aos.writeObject(new DERTaggedObject(4,this.certificates));
        
        if (this.trustedCertificates != null)
            aos.writeObject(new DERTaggedObject(5,this.trustedCertificates));
        
        if (this.usefulCertificates != null)
            aos.writeObject(new DERTaggedObject(6,this.usefulCertificates));
        
        // data objects to come...
        
        if (this.authObjects != null)
            aos.writeObject(new DERTaggedObject(8,this.authObjects));
        
        // write END_OF_STREAM
        aos.write(0);
        aos.write(0);  
        aos.close();
    }
    
    /**
     * @return the privateKeys
     */
    public SequenceOf<PKCS15PrivateKey> getPrivateKeys() {
        return this.privateKeys;
    }

    /**
     * @param privateKeys the privateKeys to set
     */
    public void setPrivateKeys(SequenceOf<PKCS15PrivateKey> privateKeys) {
        this.privateKeys = privateKeys;
    }

    /**
     * @return the publicKeys
     */
    public SequenceOf<PKCS15PublicKey> getPublicKeys() {
        return this.publicKeys;
    }

    /**
     * @param publicKeys the publicKeys to set
     */
    public void setPublicKeys(SequenceOf<PKCS15PublicKey> publicKeys) {
        this.publicKeys = publicKeys;
    }

    /**
     * @return the certificates
     */
    public SequenceOf<PKCS15Certificate> getCertificates() {
        return this.certificates;
    }

    /**
     * @param certificates the certificates to set
     */
    public void setCertificates(SequenceOf<PKCS15Certificate> certificates) {
        this.certificates = certificates;
    }

    /**
     * @return the authObjects
     */
    public SequenceOf<PKCS15AuthenticationObject> getAuthObjects() {
        return this.authObjects;
    }

    /**
     * @param authObjects the authObjects to set
     */
    public void setAuthObjects(SequenceOf<PKCS15AuthenticationObject> authObjects) {
        this.authObjects = authObjects;
    }

    /**
     * @return the trustedPublicKeys
     */
    public SequenceOf<PKCS15PublicKey> getTrustedPublicKeys() {
        return this.trustedPublicKeys;
    }

    /**
     * @param trustedPublicKeys the trustedPublicKeys to set
     */
    public void setTrustedPublicKeys(SequenceOf<PKCS15PublicKey> trustedPublicKeys) {
        this.trustedPublicKeys = trustedPublicKeys;
    }

    /**
     * @return the trustedCertificates
     */
    public SequenceOf<PKCS15Certificate> getTrustedCertificates() {
        return this.trustedCertificates;
    }

    /**
     * @param trustedCertificates the trustedCertificates to set
     */
    public void setTrustedCertificates(
            SequenceOf<PKCS15Certificate> trustedCertificates) {
        this.trustedCertificates = trustedCertificates;
    }

    /**
     * @return the usefulCertificates
     */
    public SequenceOf<PKCS15Certificate> getUsefulCertificates() {
        return this.usefulCertificates;
    }

    /**
     * @param usefulCertificates the usefulCertificates to set
     */
    public void setUsefulCertificates(
            SequenceOf<PKCS15Certificate> usefulCertificates) {
        this.usefulCertificates = usefulCertificates;
    }
    
    
}
