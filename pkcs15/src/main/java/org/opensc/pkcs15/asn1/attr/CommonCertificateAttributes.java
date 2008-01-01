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

package org.opensc.pkcs15.asn1.attr;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cmp.OOBCertHash;
import org.opensc.pkcs15.asn1.basic.KeyIdentifier;
import org.opensc.pkcs15.asn1.basic.KeyIdentifiers;
import org.opensc.pkcs15.asn1.basic.Usage;

/**
 * <PRE>
 * CommonCertificateAttributes ::= SEQUENCE {
 *      iD                    Identifier,
 *      authority             BOOLEAN DEFAULT FALSE,
 *      identifier       CredentialIdentifier {{KeyIdentifiers}} OPTIONAL,
 *      certHash              [0] OOBCertHash OPTIONAL,
 *      ...,
 *      trustedUsage          [1] Usage OPTIONAL,
 *      identifiers           [2] SEQUENCE OF CredentialIdentifier{{KeyIdentifiers}} OPTIONAL,
 *      implicitTrust         [3] BOOLEAN DEFAULT FALSE
 *      }
 * </PRE>
 * 
 * @author wglas
 */
public class CommonCertificateAttributes extends ASN1Encodable {

    private ASN1OctetString iD;
    private boolean authority;
    private KeyIdentifier identifier;
    private OOBCertHash certHash;
    private Usage trustedUsage;
    private KeyIdentifiers identifiers;
    private boolean implicitTrust;
    
    /**
     * Default constructor.
     */
    public CommonCertificateAttributes() {
        super();
    }

    /**
     * @param obj The ASN.1 object to decode.
     * @return An instance of CommonObjectAttributes.
     */
    public static CommonCertificateAttributes getInstance (Object obj)
    {
        if (obj instanceof CommonCertificateAttributes)
            return (CommonCertificateAttributes)obj;
            
        if (obj instanceof ASN1Sequence) 
        {
            ASN1Sequence seq = (ASN1Sequence)obj;
            
            Enumeration<Object> objs = seq.getObjects();
            
            CommonCertificateAttributes ret = new CommonCertificateAttributes();
            
            while (objs.hasMoreElements()) {
                
                Object o = objs.nextElement();
                
                if (o instanceof ASN1OctetString) {
                    ret.setID((ASN1OctetString)o);
                } else if (o instanceof DERBoolean) {
                    ret.setAuthority(((DERBoolean)o).isTrue());
                } else if (o instanceof ASN1Sequence) {
                    ret.setIdentifier(KeyIdentifier.getInstance(o));
                } else if (o instanceof ASN1TaggedObject) {
                    
                    ASN1TaggedObject to = (ASN1TaggedObject)o;
                    
                    switch (to.getTagNo())
                    {
                    case 0:
                        ret.setCertHash(OOBCertHash.getInstance(to.getDERObject()));
                        break;
                    case 1:
                        ret.setTrustedUsage(Usage.getInstance(to.getDERObject()));
                        break;
                    case 2:
                        ret.setIdentifiers(KeyIdentifiers.getInstance(to.getDERObject()));
                        break;
                    case 3:
                        ret.setImplicitTrust(DERBoolean.getInstance(to.getDERObject()).isTrue());
                        break;
                        
                    default:
                        throw new IllegalArgumentException("Invalid member tag ["+to.getTagNo()+"] in member of CommonCertificateAttributes ASN.1 SEQUENCE.");
                    }
                    
                } else
                    throw new IllegalArgumentException("Invalid member ["+o+"] in CommonCertificateAttributes ASN.1 SEQUENCE.");
            }
               
            return ret;
        }
        
        throw new IllegalArgumentException("CommonCertificateAttributes must be encoded as an ASN.1 SEQUENCE.");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Object()
     */
    @Override
    public DERObject toASN1Object() {
        
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (this.iD != null)
            v.add(this.iD);
        
        v.add(new DERBoolean(this.authority));
        
        if (this.identifier != null)
            v.add(this.identifier);
        
        if (this.certHash != null)
            v.add(new DERTaggedObject(0,this.certHash));
        
        if (this.trustedUsage != null)
            v.add(new DERTaggedObject(1,this.trustedUsage));
        
        if (this.identifiers != null)
            v.add(new DERTaggedObject(2,this.identifiers));
        
        v.add(new DERTaggedObject(3,new DERBoolean(this.implicitTrust)));
        
        return new DERSequence(v);
    }

    /**
     * @return the iD
     */
    public ASN1OctetString getID() {
        return this.iD;
    }

    /**
     * @param id the iD to set
     */
    public void setID(ASN1OctetString id) {
        this.iD = id;
    }

    /**
     * @return the authority
     */
    public boolean isAuthority() {
        return this.authority;
    }

    /**
     * @param authority the authority to set
     */
    public void setAuthority(boolean authority) {
        this.authority = authority;
    }

    /**
     * @return the identifier
     */
    public KeyIdentifier getIdentifier() {
        return this.identifier;
    }

    /**
     * @param identifier the identifier to set
     */
    public void setIdentifier(KeyIdentifier identifier) {
        this.identifier = identifier;
    }

    /**
     * @return the certHash
     */
    public OOBCertHash getCertHash() {
        return this.certHash;
    }

    /**
     * @param certHash the certHash to set
     */
    public void setCertHash(OOBCertHash certHash) {
        this.certHash = certHash;
    }

    /**
     * @return the trustedUsage
     */
    public Usage getTrustedUsage() {
        return this.trustedUsage;
    }

    /**
     * @param trustedUsage the trustedUsage to set
     */
    public void setTrustedUsage(Usage trustedUsage) {
        this.trustedUsage = trustedUsage;
    }

    /**
     * @return the identifiers
     */
    public KeyIdentifiers getIdentifiers() {
        return this.identifiers;
    }

    /**
     * @param identifiers the identifiers to set
     */
    public void setIdentifiers(KeyIdentifiers identifiers) {
        this.identifiers = identifiers;
    }

    /**
     * @return the implicitTrust
     */
    public boolean isImplicitTrust() {
        return this.implicitTrust;
    }

    /**
     * @param implicitTrust the implicitTrust to set
     */
    public void setImplicitTrust(boolean implicitTrust) {
        this.implicitTrust = implicitTrust;
    }
}
