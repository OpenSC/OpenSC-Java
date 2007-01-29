/***********************************************************
 * $Id$
 * 
 * PKCS11 provider of the OpenSC project http://www.opensc-project.org
 *
 * Copyright (C) 2002-2007 ev-i Informationstechnologie GmbH
 *
 * Created: Jan 27, 2007
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 * 
 ***********************************************************/

package org.opensc.test.pkcs11;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.opensc.pkcs11.PKCS11LoadStoreParameter;
import org.opensc.pkcs11.wrap.PKCS11PrivateKey;
import org.opensc.pkcs11.wrap.PKCS11PublicKey;
import org.opensc.util.PKCS11Id;

/**
 * Test storing of X509 certificates onto the token.
 * 
 * @author wglas
 */
public class SaveCertificateTest extends PKCS11ProviderTestCase {

    BouncyCastleProvider bcProvider;
    
    /* (non-Javadoc)
     * @see org.opensc.test.pkcs11.PKCS11ProviderTestCase#setUp()
     */
    @Override
    public void setUp() throws IOException {
        
        this.bcProvider = new BouncyCastleProvider();
        Security.addProvider(this.bcProvider);
        
        super.setUp();
    }

    /* (non-Javadoc)
     * @see org.opensc.test.pkcs11.PKCS11ProviderTestCase#tearDown()
     */
    @Override
    public void tearDown() {
        super.tearDown();
        
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    public void testX509CertificateGeneration() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, InvalidKeyException, IllegalStateException, SignatureException, InvalidKeySpecException
    {
        KeyStore ks = KeyStore.getInstance("PKCS11","OpenSC-PKCS11");

        PKCS11LoadStoreParameter params  = new PKCS11LoadStoreParameter();
        
        PINEntry pe = new PINEntry();
        
        params.setWaitForSlot(true);
        params.setProtectionCallback(pe);
        params.setSOProtectionCallback(pe);
        params.setWriteEnabled(true);
        params.setEventHandler(pe);
        
        ks.load(params);

        // well, find a private key.
        Enumeration<String> aliases=ks.aliases();
            
        String alias = null;
        
        while (aliases.hasMoreElements())
        {
            String s = aliases.nextElement();
            if (ks.isKeyEntry(s))
            {
                alias = s;
                break;
            }
        }   
            
        assertNotNull(alias);
        
        PKCS11PrivateKey privKey = (PKCS11PrivateKey) ks.getKey(alias, null);
        PKCS11PublicKey pubKey = privKey.getPublicKey();
        
        KeyFactory kf = KeyFactory.getInstance(pubKey.getAlgorithm());
            
        PublicKey dup=(PublicKey) kf.translateKey(pubKey);
            
        PKCS11Id enc1=new PKCS11Id(pubKey.getEncoded());
        PKCS11Id enc2=new PKCS11Id(dup.getEncoded());
            
        System.out.println("enc1="+enc1);
        System.out.println("enc2="+enc2);
        
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        long now = System.currentTimeMillis();
        
        certGen.setSerialNumber(BigInteger.valueOf(now));
        
        X509Principal subject = new X509Principal("CN=PKCS11 Test CA,DC=opensc-project,DC=org");
        
        certGen.setIssuerDN(subject);
        certGen.setSubjectDN(subject);
        
        Date from_date = new Date(now);
        certGen.setNotBefore(from_date);
        Calendar cal = new GregorianCalendar();
        cal.setTime(from_date);
        cal.add(Calendar.YEAR, 4);
        Date to_date = cal.getTime();
        certGen.setNotAfter(to_date);

        certGen.setPublicKey(dup);
        certGen.setSignatureAlgorithm("SHA1withRSA");
        certGen.addExtension(X509Extensions.BasicConstraints, true,
                new BasicConstraints(false));
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(
                KeyUsage.digitalSignature | KeyUsage.keyEncipherment
                        | KeyUsage.keyCertSign | KeyUsage.cRLSign));
        
        
        X509Certificate x509 = certGen.generate(privKey,"OpenSC-PKCS11");
        
        ks.setCertificateEntry(alias, x509);
    }
}
