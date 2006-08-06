/***********************************************************
 * $Id$
 * 
 * Copyright (C) 2002-2006 ev-i Informationstechnologie GmbH
 *
 * Created: Jul 16, 2006
 *
 * Author: Wolfgang Glas/ev-i
 * 
 ***********************************************************/

package org.opensc.pkcs11;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import junit.framework.TestCase;

import org.opensc.pkcs11.wrap.PKCS11Certificate;
import org.opensc.pkcs11.wrap.PKCS11Exception;
import org.opensc.pkcs11.wrap.PKCS11Mechanism;
import org.opensc.pkcs11.wrap.PKCS11PrivateKey;
import org.opensc.pkcs11.wrap.PKCS11PublicKey;
import org.opensc.pkcs11.wrap.PKCS11Session;
import org.opensc.pkcs11.wrap.PKCS11Slot;

/**
 * JUnit test for the PKCS11 provider.
 *
 * @author wglas
 */
public class TestProvider extends TestCase
{
	PKCS11Provider provider;
	byte[] testData;
	
	/**
	 * Constructs a default instance of the provider test class.
	 */
	public TestProvider()
	{
		super();
	}

	public void setUp() throws IOException
	{	
		// Add provider "SunPKCS11-OpenSC"
		provider = new PKCS11Provider("/usr/lib/opensc-pkcs11.so");
		Security.addProvider(provider);
				
		Provider providers[] = Security.getProviders();
		for (Provider p : providers)
			System.out.println("Found provider: " + p.getName());
		
		testData = new byte[199];
		
		Random random = new Random(System.currentTimeMillis());
		
		random.nextBytes(testData);
	}
	
	public void tearDown()
	{
		provider.cleanup();
		provider = null;
		testData = null;
		Security.removeProvider("OpenSC-PKCS11");
	}
	
	public void testKeyStore() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, PKCS11Exception, UnrecoverableKeyException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		KeyStore ks = KeyStore.getInstance("PKCS11","OpenSC-PKCS11");

		PKCS11LoadStoreParameter params  = new PKCS11LoadStoreParameter();
		
		params.setWaitForSlot(true);
		params.setProtectionParameter(new KeyStore.CallbackHandlerProtection(new PINEntry()));
		
		ks.load(params);
		
		Enumeration<String> aliases = ks.aliases();
		
		while (aliases.hasMoreElements())
		{
			String alias = aliases.nextElement();
			
			System.out.println("alias="+alias);
			
			System.out.println(" isKey="+ks.isKeyEntry(alias));
			System.out.println(" isCertificate="+ks.isCertificateEntry(alias));
			
			if (ks.isCertificateEntry(alias))
			{
				Certificate certificate = ks.getCertificate(alias);
				System.out.println(" certificate="+certificate);
				System.out.println(" certAlias="+ks.getCertificateAlias(certificate));
				
				Certificate [] chain = ks.getCertificateChain(alias);
				
				for (int i=0;i<chain.length;++i)
				{
					X509Certificate x509 = (X509Certificate)chain[i];
					
					System.out.println(" chain["+i+"].subject="+x509.getSubjectX500Principal());
					System.out.println(" chain["+i+"].issuer="+x509.getSubjectX500Principal());
					System.out.println(" chain["+i+"].serial="+x509.getSerialNumber());
				}
			}
		}
		
	}
	
	public void testSignature() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, PKCS11Exception, UnrecoverableKeyException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		KeyStore ks = KeyStore.getInstance("PKCS11","OpenSC-PKCS11");

		PKCS11LoadStoreParameter params  = new PKCS11LoadStoreParameter();
		
		params.setWaitForSlot(true);
		params.setProtectionParameter(new KeyStore.CallbackHandlerProtection(new PINEntry()));
		
		ks.load(params);
		
		Enumeration<String> aliases = ks.aliases();
		
		while (aliases.hasMoreElements())
		{
			String alias = aliases.nextElement();
			
			System.out.println("alias="+alias);
			
			System.out.println(" isKey="+ks.isKeyEntry(alias));
			System.out.println(" isCertificate="+ks.isCertificateEntry(alias));
			
			if (ks.isCertificateEntry(alias))
			{
				Certificate certificate = ks.getCertificate(alias);

				if (ks.isKeyEntry(alias))
				{
					Key key = ks.getKey(alias,null);
					
					System.out.println("certificate="+certificate);
					System.out.println("key.class="+key.getClass());
					
					assertTrue(provider.getService("Signature","SHA1withRSA").supportsParameter(key));
					
					//
					// We do not specify the provider here in order to test
					// the delayed provider selection describe in
					// http://java.sun.com/j2se/1.5.0/docs/guide/security/p11guide.html
					//
					Signature sig = Signature.getInstance("SHA1withRSA" /*,provider*/);
					sig.initSign((PrivateKey)key);
					System.out.println("sig.provider="+sig.getProvider().getName());
					
					sig.update(testData);
					byte[] signature = sig.sign();
					
					System.out.print("sig=");
					
					for (byte b:signature)
					{
						System.out.print(String.format("%02x",((int)b)&0xff));
					}
					System.out.println(".");
					
					Signature vfy = Signature.getInstance("SHA1withRSA");
					vfy.initVerify(certificate);
					System.out.println("vfy.provider="+vfy.getProvider().getName());
					vfy.update(testData);
					assertEquals(vfy.verify(signature),true);
				}
			}
		}		
	}
	
	public void testDecryption() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, PKCS11Exception, UnrecoverableKeyException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		KeyStore ks = KeyStore.getInstance("PKCS11","OpenSC-PKCS11");

		PKCS11LoadStoreParameter params  = new PKCS11LoadStoreParameter();
		
		params.setWaitForSlot(true);
		params.setProtectionParameter(new KeyStore.CallbackHandlerProtection(new PINEntry()));
		
		ks.load(params);
		
		Enumeration<String> aliases = ks.aliases();
		
		while (aliases.hasMoreElements())
		{
			String alias = aliases.nextElement();
			
			System.out.println("alias="+alias);
			
			System.out.println(" isKey="+ks.isKeyEntry(alias));
			System.out.println(" isCertificate="+ks.isCertificateEntry(alias));
			
			if (ks.isCertificateEntry(alias))
			{
				Certificate certificate = ks.getCertificate(alias);

				if (ks.isKeyEntry(alias))
				{
					Key key = ks.getKey(alias,null);
					
					System.out.println("key.class="+key.getClass());
					
					Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					enc.init(Cipher.ENCRYPT_MODE,certificate);
					byte[] encData = enc.doFinal(testData);

					Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding",provider);
					dec.init(Cipher.DECRYPT_MODE,key);
					byte[] origData = dec.doFinal(encData);
					
					assertEquals(testData,origData);
				}
			}
		}		
	}
	
	public void testWrapper() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, PKCS11Exception
	{
		List<PKCS11Slot> slots = PKCS11Slot.enumerateSlots(provider);
		
		char [] pin = null;
		
		for (Iterator<PKCS11Slot> iter = slots.iterator(); iter.hasNext();)
		{
			PKCS11Slot slot = iter.next();
			
			System.out.println("ID = "+slot.getId());
			System.out.println("tokenPresent = "+slot.isTokenPresent());
			System.out.println("hardwareDevice = "+slot.isHardwareDevice());
			System.out.println("removableDevice = "+slot.isRemovableDevice());
			System.out.println("description = "+slot.getDescription());
			System.out.println("manufacturer = "+slot.getManufaturer());
			System.out.println("hardwareVersion = "+slot.getHardwareVersion());
			System.out.println("firmwareVersion = "+slot.getFirmwareVersion());
			
			if (slot.isTokenPresent())
			{
				PKCS11Mechanism mechanisms[] = slot.getMechanisms();
			
				for (int i = 0; i < mechanisms.length; i++)
				{
					System.out.println("mecahnism["+i+"].type = "+mechanisms[i].getType()+" ("+mechanisms[i].getTypeName()+")");
					System.out.println("mechanism["+i+"].minKeySize = "+mechanisms[i].getMinKeySize());
					System.out.println("mechanism["+i+"].maxKeySize = "+mechanisms[i].getMaxKeySize());
					System.out.println("mechanism["+i+"].flags = "+mechanisms[i].getFlags());
				}
				
				PKCS11Session session = PKCS11Session.open(slot,PKCS11Session.OPEN_MODE_READ_ONLY);
				
				List<PKCS11Certificate> certificates = PKCS11Certificate.getCertificates(session);
				
				for (PKCS11Certificate certificate : certificates)
				{
					System.out.println("certificate.id = "+certificate.getId());
					System.out.println("certificate.label = "+certificate.getLabel());
					System.out.println("certificate.subject = "+certificate.getSubject());
					System.out.println("certificate.issuer = "+certificate.getIssuer());
					System.out.println("certificate.serial = "+certificate.getSerial());
					System.out.println("certificate.certificate = "+certificate.getCertificate());
				}
				
				List<PKCS11PublicKey> pubkeys = PKCS11PublicKey.getPublicKeys(session);
				
				for (PKCS11PublicKey pubkey : pubkeys)
				{
					System.out.println("pubkey.id = "+pubkey.getId());
					System.out.println("pubkey.label = "+pubkey.getLabel());
					System.out.println("pubkey.keyType = "+pubkey.getKeyType());
					System.out.println("pubkey.keyBits = "+pubkey.getKeyBits());
					
					byte[] data = pubkey.getEncoded();
					
					System.out.println("pubkey.data.length = "+data.length);
				}
				
				if (slot.hasTokenProtectedAuthPath())
					pin = null;
				else
					pin = PINEntry.getPIN("Enter PIN for slot "+slot.getId());
					
				session.loginUser(pin);
				
				List<PKCS11PrivateKey> privkeys = PKCS11PrivateKey.getPrivateKeys(session);
				
				for (PKCS11PrivateKey privkey : privkeys)
				{
					System.out.println("privkey.id = "+privkey.getId());
					System.out.println("privkey.label = "+privkey.getLabel());
					System.out.println("privkey.keyType = "+privkey.getKeyType());
					System.out.println("privkey.keyBits = "+privkey.getKeyBits());
				}
			}
			//slot.open(PKCS11Slot.OPEN_MODE_READ_ONLY);
			//slot.open(PKCS11Slot.OPEN_MODE_READ_ONLY);
		}
		
	}
	
}
