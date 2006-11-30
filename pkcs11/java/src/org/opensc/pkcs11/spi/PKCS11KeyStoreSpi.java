/***********************************************************
 * $Id$
 * 
 * PKCS11 provider of the OpenSC project http://www.opensc-project.org
 * 
 * Copyright (C) 2006 ev-i Informationstechnologie GmbH
 *
 * Created: Jul 16, 2006
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

package org.opensc.pkcs11.spi;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.KeyStore.CallbackHandlerProtection;
import java.security.KeyStore.Entry;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensc.pkcs11.PKCS11EventCallback;
import org.opensc.pkcs11.PKCS11LoadStoreParameter;
import org.opensc.pkcs11.PKCS11Provider;
import org.opensc.pkcs11.wrap.PKCS11Certificate;
import org.opensc.pkcs11.wrap.PKCS11Exception;
import org.opensc.pkcs11.wrap.PKCS11PrivateKey;
import org.opensc.pkcs11.wrap.PKCS11Session;
import org.opensc.pkcs11.wrap.PKCS11Slot;

/**
 * This is a JAVA KeyStore, which accesses a slot on a PKCS#11 cryptographic token.
 *
 * @author wglas
 */
public class PKCS11KeyStoreSpi extends KeyStoreSpi
{
	static private final Log log = LogFactory.getLog(PKCS11KeyStoreSpi.class);

	static private final int MAX_SIMILAR_CERTIFICATES = 32;
	
	private class PKCS11KSEntry implements Entry
	{
		public Date creationDate;
		public PKCS11Certificate certificate;
		private Certificate decodedCertificate;
		public PKCS11PrivateKey privateKey;
		
		PKCS11KSEntry(PKCS11PrivateKey privateKey)
		{
			this.creationDate = new Date();
			this.privateKey = privateKey;
		}
		
		PKCS11KSEntry(PKCS11Certificate certificate)
		{
			this.creationDate = new Date();
			this.certificate = certificate;
		}
		
		public Certificate getDecodedCertificate() throws PKCS11Exception, CertificateException
		{
			if (this.decodedCertificate == null && this.certificate != null)
				this.decodedCertificate = this.certificate.getCertificate();
			
			return this.decodedCertificate;
		}
	}
	
	private final PKCS11Provider provider;
	private PKCS11Slot slot;
	private PKCS11Session session;
	private Map<String,PKCS11KSEntry> entries;
	
	/**
	 * Contruct a PKCS11 KeyStore.
	 */
	public PKCS11KeyStoreSpi(PKCS11Provider provider, String algorithm)
	{
		super();
		this.provider = provider;
		
		if (algorithm != "PKCS11")
			throw new ProviderException("Algorithm for PKCS11 KeyStore can only be \"PKCS11\".");
	}
	
	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineGetKey(java.lang.String, char[])
	 */
	@Override
	public Key engineGetKey(String name, char[] pin)
			throws NoSuchAlgorithmException, UnrecoverableKeyException
	{
		PKCS11KSEntry entry = this.entries.get(name);
		if (entry == null) return null;
		return entry.privateKey;
	}
	
	/**
	 * Returns all certificates for the given X500Principal.
	 * 
	 * @param subject The subject to search for.
	 * @return All certificates, which match this subject.
	 */
	private Map<String,PKCS11KSEntry> getAllCertificatesForSubject(X500Principal subject)
	{
		Map<String,PKCS11KSEntry> ret = new HashMap<String,PKCS11KSEntry>();
		
		String subj = subject.toString();
		
		PKCS11KSEntry entry = this.entries.get(subj);
		
		if (entry != null)
		{
			ret.put(subj,entry);
			
			int i = 1;
			
			do
			{
				++i;
				String name = String.format("%s_%02X",subj,i);
				
				entry = this.entries.get(name);
				if (entry != null) ret.put(name,entry);
			}
			while (entry != null && i < MAX_SIMILAR_CERTIFICATES);
		}
		
		
		return ret;
	}

	private static boolean isRootCA(X509Certificate cert) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException
	{
		if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()))
			return false;
		
		cert.verify(cert.getPublicKey());
		return true;
	}
	
	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineGetCertificateChain(java.lang.String)
	 */
	@Override
	public Certificate[] engineGetCertificateChain(String name)
	{
		Certificate endEntity = engineGetCertificate(name);
		
		if (endEntity == null) return null;
		
		if (!(endEntity instanceof X509Certificate))
		{
			log.error("engineGetCertificateChain: Only X.509 certificates are supported.");
			return null;
		}
		
		List<Certificate> ret = new ArrayList<Certificate>();
		
		ret.add(endEntity);
		
		X509Certificate x509Certificate = (X509Certificate)endEntity;
		
		try
		{
			// OK ,this is acrude form of certificate chain evaluation.
			// Assuming, that the upper layer does a more detailed anlysis of the
			// validity period and key extensions, we only search the chain by
			// finding the issuing certificate on the token using the issuer DN
			// and trying to check the Signature on the certificate using the
			// public key on the next certificate.
			while (!isRootCA(x509Certificate))
			{
				Map<String,PKCS11KSEntry> centries =
					getAllCertificatesForSubject(x509Certificate.getIssuerX500Principal());
				
				X509Certificate x509NextCert = null;
				
				for (PKCS11KSEntry entry : centries.values())
				{
					Certificate next = entry.getDecodedCertificate();
									
					X509Certificate x509Next = (X509Certificate)next;
				
					if (!x509Next.getSubjectX500Principal().equals(x509Certificate.getIssuerX500Principal()))
						continue;
						
					try {
						x509Certificate.verify(x509Next.getPublicKey());
						x509NextCert = x509Next;
						break;
					}
					catch (Exception e) {
						log.warn("Exception during evaluation of certificate chain:",e);
					}
				}
				
				if (x509NextCert == null)
				{
					throw new CertificateException("Cannot find the issuing CA for certificate ["+x509Certificate+"].");
				}
				
				x509Certificate = x509NextCert;
				ret.add(x509Certificate);
			}
			
			return ret.toArray(new Certificate[0]);
			
		} catch (Exception e)
		{
			log.error("Exception caught during analysis of the certificate chain:",e);
		}
		return null;
	}

	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineGetCertificate(java.lang.String)
	 */
	@Override
	public Certificate engineGetCertificate(String name)
	{
		PKCS11KSEntry entry = this.entries.get(name);
		if (entry == null) return null;
		try
		{
			return entry.getDecodedCertificate();
		} catch (PKCS11Exception e)
		{
			log.error("PKCS11 Error decoding Certificate for entry "+name+":",e);
		} catch (CertificateException e)
		{
			log.error("Certificate Error decoding Certificate for entry "+name+":",e);
		}
		return null;
	}

	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineGetCreationDate(java.lang.String)
	 */
	@Override
	public Date engineGetCreationDate(String name)
	{
		PKCS11KSEntry entry = this.entries.get(name);
		if (entry == null) return null;
		return entry.creationDate;
	}

	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineSetKeyEntry(java.lang.String, java.security.Key, char[], java.security.cert.Certificate[])
	 */
	@Override
	public void engineSetKeyEntry(String name, Key key, char[] pin,
			Certificate[] certificateChain) throws KeyStoreException
	{
		throw new KeyStoreException("setKeyEntry is unimplmented.");
	}

	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineSetKeyEntry(java.lang.String, byte[], java.security.cert.Certificate[])
	 */
	@Override
	public void engineSetKeyEntry(String name, byte[] pin, Certificate[] certificateChain)
			throws KeyStoreException
	{
		throw new KeyStoreException("setKeyEntry is unimplmented.");
	}

	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineSetCertificateEntry(java.lang.String, java.security.cert.Certificate)
	 */
	@Override
	public void engineSetCertificateEntry(String name, Certificate certificate)
			throws KeyStoreException
	{
		throw new KeyStoreException("setCertificateEntry is unimplmented.");
	}

	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineDeleteEntry(java.lang.String)
	 */
	@Override
	public void engineDeleteEntry(String name) throws KeyStoreException
	{
		throw new KeyStoreException("deleteEntry is unimplemented.");
	}

	
	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineAliases()
	 */
	@Override
	public Enumeration<String> engineAliases()
	{
		// Enumeration is efinitely a misconception, as you can see
		// by the code below...
		Set<String> keys = this.entries.keySet();
		Vector<String> sv = new Vector<String>(keys.size());
		sv.addAll(keys);
		
		return sv.elements();
	}

	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineContainsAlias(java.lang.String)
	 */
	@Override
	public boolean engineContainsAlias(String name)
	{
		return this.entries.containsKey(name);
	}

	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineSize()
	 */
	@Override
	public int engineSize()
	{
		return this.entries.size();
	}

	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineIsKeyEntry(java.lang.String)
	 */
	@Override
	public boolean engineIsKeyEntry(String name)
	{
		PKCS11KSEntry entry = this.entries.get(name);
		if (entry == null) return false;
	
		return entry.privateKey != null;
	}

	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineIsCertificateEntry(java.lang.String)
	 */
	@Override
	public boolean engineIsCertificateEntry(String name)
	{
		PKCS11KSEntry entry = this.entries.get(name);
		if (entry == null) return false;
	
		return entry.certificate != null;
	}

	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineGetCertificateAlias(java.security.cert.Certificate)
	 */
	@Override
	public String engineGetCertificateAlias(Certificate certificate)
	{
		if (! (certificate instanceof X509Certificate))
		{
			log.error("engineGetCertificateAlias: Only X.509 certificates are supported.");
		}
		
		X509Certificate x509Certificate = (X509Certificate)certificate;
		
		X500Principal subject = x509Certificate.getSubjectX500Principal();
		
		Map<String,PKCS11KSEntry> centries = getAllCertificatesForSubject(subject);
		
		for (String name : centries.keySet())
		{
			try
			{
				PKCS11KSEntry entry = centries.get(name);
				
				if (entry.certificate != null &&
					entry.getDecodedCertificate().equals(certificate))
					return name;
				
			} catch (PKCS11Exception e)
			{
				log.error("PKCS11 Error decoding Certificate for entry "+name+":",e);
			} catch (CertificateException e)
			{
				log.error("Certificate Error decoding Certificate for entry "+name+":",e);
			}
		}
		
		return null;
	}

	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineStore(java.io.OutputStream, char[])
	 */
	@Override
	public void engineStore(OutputStream arg0, char[] arg1) throws IOException,
			NoSuchAlgorithmException, CertificateException
	{
		throw new NoSuchAlgorithmException("PKCS11 key store does not support a store operation.");
	}
	
	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineLoad(java.io.InputStream, char[])
	 */
	@Override
	public void engineLoad(InputStream file, char[] pin) throws IOException,
			NoSuchAlgorithmException, CertificateException
	{
		if (file != null)
			throw new IOException ("PKCS11 Key Store requires a null InputStream a the first argument.");
	
		PKCS11LoadStoreParameter param = new PKCS11LoadStoreParameter();
		
		param.setProtectionParameter(new PasswordProtection(pin));
		
		engineLoad(param);
	}

	private static void changeEvent(int ev, CallbackHandler eventHandler, PKCS11EventCallback cb) throws IOException
	{
		cb.setEvent(ev);
		if (eventHandler==null) return;
		
		try
		{
			eventHandler.handle(new Callback[]{cb});
		} catch (UnsupportedCallbackException e)
		{
			log.warn("PKCSEventCallback not supported by CallbackHandler ["+eventHandler.getClass()+"]",e);
		}
	}
	
	private static void eventFailed(CallbackHandler eventHandler, PKCS11EventCallback cb, Exception e) throws IOException
	{
		int fe;
		
		switch (cb.getEvent())
		{
		default:
			fe = PKCS11EventCallback.INITIALIZATION_FAILED;
			break;
			
		case PKCS11EventCallback.WAITING_FOR_CARD:
			fe = PKCS11EventCallback.CARD_WAIT_FAILED;
			break;
			
		case PKCS11EventCallback.WAITING_FOR_SW_PIN:
		case PKCS11EventCallback.WAITING_FOR_SW_SO_PIN:
			// an IOException during software PIN entry is interpreted as an abort of
			// the PIN entry process. This is done so, because there is no standard exception
			// for such a situation defined.
			if ((e instanceof IOException) &&
					!(e instanceof PKCS11Exception))
			{
				fe = (cb.getEvent() == PKCS11EventCallback.WAITING_FOR_SW_SO_PIN) ?
						PKCS11EventCallback.SO_PIN_ENTRY_ABORTED :
							PKCS11EventCallback.PIN_ENTRY_ABORTED;
				break;
			}
		
			// A PKCS11Exception with CKR_FUNCTION_CANCELED od CKR_CANCEL
			// is interpreted as a PIN entry abort by the user.
			if (e instanceof PKCS11Exception)
			{
				PKCS11Exception p11e = (PKCS11Exception)e;
				
				if (p11e.getErrorCode() == PKCS11Exception.CKR_FUNCTION_CANCELED ||
						p11e.getErrorCode() == PKCS11Exception.CKR_CANCEL)
				{
					fe = (cb.getEvent() == PKCS11EventCallback.WAITING_FOR_SW_SO_PIN) ?
							PKCS11EventCallback.SO_PIN_ENTRY_ABORTED :
								PKCS11EventCallback.PIN_ENTRY_ABORTED;
					break;
				}
			}
			
			fe = (cb.getEvent() == PKCS11EventCallback.WAITING_FOR_SW_SO_PIN) ?
					PKCS11EventCallback.SO_PIN_ENTRY_FAILED :
						PKCS11EventCallback.PIN_ENTRY_FAILED;
			break;
			
		case PKCS11EventCallback.HW_AUTHENTICATION_IN_PROGRESS:
		case PKCS11EventCallback.SO_HW_AUTHENTICATION_IN_PROGRESS:
			// A PKCS11Exception with CKR_FUNCTION_CANCELED od CKR_CANCEL
			// is interpreted as an authentication abort by the user.
			if (e instanceof PKCS11Exception)
			{
				PKCS11Exception p11e = (PKCS11Exception)e;
				
				if (p11e.getErrorCode() == PKCS11Exception.CKR_FUNCTION_CANCELED ||
						p11e.getErrorCode() == PKCS11Exception.CKR_CANCEL)
				{
					fe = (cb.getEvent() == PKCS11EventCallback.SO_HW_AUTHENTICATION_IN_PROGRESS) ?
							PKCS11EventCallback.SO_AUHENTICATION_ABORTED :
								PKCS11EventCallback.AUHENTICATION_ABORTED;
					break;
				}
			}

			fe = (cb.getEvent() == PKCS11EventCallback.SO_HW_AUTHENTICATION_IN_PROGRESS) ?
					PKCS11EventCallback.SO_AUHENTICATION_FAILED :
						PKCS11EventCallback.AUHENTICATION_FAILED;
			break;
			
		case PKCS11EventCallback.PIN_AUTHENTICATION_IN_PROGRESS:
			fe = PKCS11EventCallback.AUHENTICATION_FAILED;
			break;
			
		case PKCS11EventCallback.SO_PIN_AUTHENTICATION_IN_PROGRESS:
			fe = PKCS11EventCallback.SO_AUHENTICATION_FAILED;
			break;
		}
		
		changeEvent(fe,eventHandler,cb);
	}
	
	/* (non-Javadoc)
	 * @see java.security.KeyStoreSpi#engineLoad(java.security.KeyStore.LoadStoreParameter)
	 */
	@Override
	public void engineLoad(LoadStoreParameter param) throws IOException,
			NoSuchAlgorithmException, CertificateException
	{
		PKCS11EventCallback evCb = new PKCS11EventCallback(PKCS11EventCallback.NO_EVENT);

		ProtectionParameter pp = param.getProtectionParameter();
		
		CallbackHandler eventHandler = null;
		if (param instanceof PKCS11LoadStoreParameter)
			eventHandler = ((PKCS11LoadStoreParameter)param).getEventHandler();
		
		try
		{
			if (this.slot != null)
			{
				this.slot.destroy();
				this.slot = null;
				this.session = null;
				this.entries = null;
			}

			PKCS11LoadStoreParameter p11_param = null;
			if (param instanceof PKCS11LoadStoreParameter)
				p11_param = (PKCS11LoadStoreParameter) param;
			
			// get the new slot.
			PKCS11Slot s = null;

			// OK, the user knows, which slot is desired.
			if (p11_param != null && p11_param.getSlotId() != null)
			{
				s = new PKCS11Slot(this.provider, p11_param.getSlotId());
				
				// is there a token ?
				// no token, but user wants to wait.
				if (!s.isTokenPresent() && p11_param.isWaitForSlot())
				{
					s.destroy();

					changeEvent(PKCS11EventCallback.WAITING_FOR_CARD,eventHandler,evCb);

					// OK, someone might argue, that we could intrduce a loop
					// here in order to wait for the right token.
					// For the moment, I prefer to throw an exception, if the
					// user
					// inserts a token into the wrong slot.
					s = PKCS11Slot.waitForSlot(this.provider);

					if (s.getId() != p11_param.getSlotId().longValue())
					{
						s.destroy();
						throw new PKCS11Exception(
								"A token has been inserted in slot number "
										+ s.getId()
										+ " instead of slot number "
										+ p11_param.getSlotId());
					}
				}

			}
			// The user does not know, which slot is desired, so go and find
			// one.
			else
			{
				List<PKCS11Slot> slots = PKCS11Slot
						.enumerateSlots(this.provider);

				for (PKCS11Slot checkSlot : slots)
				{
					if (s == null && checkSlot.isTokenPresent())
						s = checkSlot;
					else
						checkSlot.destroy();
				}

				// not a single token found and user wants to wait.
				if (s == null && p11_param != null && p11_param.isWaitForSlot())
				{
					changeEvent(PKCS11EventCallback.WAITING_FOR_CARD,eventHandler,evCb);
					s = PKCS11Slot.waitForSlot(this.provider);
				}
			}

			// So, did we finally find a slot ?
			if (s == null)
			{
				throw new PKCS11Exception(
						"Could not find a valid slot with a present token.");
			} else if (!s.isTokenPresent())
			{
                long slotId = s.getId();
				s.destroy();
				throw new PKCS11Exception(
						"No token is present in the given slot number "
								+ slotId);
			}

			this.slot = s;

			int open_mode = PKCS11Session.OPEN_MODE_READ_ONLY;
			
			if (p11_param != null && p11_param.isWriteEnabled())
				open_mode = PKCS11Session.OPEN_MODE_READ_WRITE;
			
			// open the session.
			this.session = PKCS11Session.open(this.slot,open_mode);
			
			if (p11_param != null)
			{
				ProtectionParameter so_pp = p11_param.getSOProtectionParameter();
				if (so_pp instanceof PasswordProtection)
				{
					changeEvent(PKCS11EventCallback.SO_PIN_AUTHENTICATION_IN_PROGRESS,eventHandler,evCb);
					this.session.loginSO(((PasswordProtection)so_pp).getPassword());
					changeEvent(PKCS11EventCallback.SO_AUHENTICATION_SUCEEDED,eventHandler,evCb);
				}
				else if (so_pp instanceof CallbackHandlerProtection)
				{
					char [] pin = null;
					// do authenticate with the protected auth method of the token,
					// if this is possible, otherwise use the callback to authenticate.
					if (this.slot.hasTokenProtectedAuthPath())
					{
						changeEvent(PKCS11EventCallback.SO_HW_AUTHENTICATION_IN_PROGRESS,eventHandler,evCb);
					}
					else
					{
						changeEvent(PKCS11EventCallback.WAITING_FOR_SW_SO_PIN,eventHandler,evCb);

						CallbackHandler cbh =
							((CallbackHandlerProtection)so_pp).getCallbackHandler();
					
						PasswordCallback pcb = new PasswordCallback("Please enter the SO pin:",false);
						cbh.handle(new Callback[] { pcb });
						pin = pcb.getPassword();
						changeEvent(PKCS11EventCallback.SO_PIN_AUTHENTICATION_IN_PROGRESS,eventHandler,evCb);
					}
					
                    this.session.loginSO(pin);
					changeEvent(PKCS11EventCallback.SO_AUHENTICATION_SUCEEDED,eventHandler,evCb);
				}
			}

			if (pp instanceof PasswordProtection)
			{
				changeEvent(PKCS11EventCallback.PIN_AUTHENTICATION_IN_PROGRESS,eventHandler,evCb);
				this.session.loginUser(((PasswordProtection)pp).getPassword());
				changeEvent(PKCS11EventCallback.AUHENTICATION_SUCEEDED,eventHandler,evCb);
			}
			else if (pp instanceof CallbackHandlerProtection)
			{
				char [] pin = null;
				// do authenticate with the protected auth method of the token,
				// if this is possible, otherwise use the callback to authenticate. 
				if (this.slot.hasTokenProtectedAuthPath())
				{
					changeEvent(PKCS11EventCallback.HW_AUTHENTICATION_IN_PROGRESS,eventHandler,evCb);
				}
				else
				{
					changeEvent(PKCS11EventCallback.WAITING_FOR_SW_PIN,eventHandler,evCb);

					CallbackHandler cbh =
						((CallbackHandlerProtection)pp).getCallbackHandler();
				
					PasswordCallback pcb = new PasswordCallback("Please enter the user pin:",false);
					cbh.handle(new Callback[] { pcb });
					
					pin = pcb.getPassword();
					changeEvent(PKCS11EventCallback.PIN_AUTHENTICATION_IN_PROGRESS,eventHandler,evCb);
				}

				this.session.loginUser(pin);
				changeEvent(PKCS11EventCallback.AUHENTICATION_SUCEEDED,eventHandler,evCb);
			}

			// OK, the session is up and running, now get the certificates
			// and keys.
			this.entries = new HashMap<String,PKCS11KSEntry>();
			
			List<PKCS11PrivateKey> privKeys =
				PKCS11PrivateKey.getPrivateKeys(this.session);
			
			Map<Integer,PKCS11KSEntry> privKeysById =
				new HashMap<Integer,PKCS11KSEntry>();
			
			for (PKCS11PrivateKey privKey : privKeys)
			{
				privKeysById.put(privKey.getId(),new PKCS11KSEntry(privKey));
			}
			
			List<PKCS11Certificate> certificates =
				PKCS11Certificate.getCertificates(this.session);
			
			for (PKCS11Certificate certificate : certificates)
			{
				// contruct a unique name for certificate entries.
				String subj = certificate.getSubject().toString();
				String name = subj;
				
				name = subj;
				
				int i = 1;
					
				while (this.entries.containsKey(name) && i < MAX_SIMILAR_CERTIFICATES)
				{
					++i;
					name = String.format("%s_%02X",subj,i);
				}
				
				if (i >= MAX_SIMILAR_CERTIFICATES) {
					throw new CertificateException("More than "+MAX_SIMILAR_CERTIFICATES+
							" instances of the same certificate subject ["+subj+
							"]found on the token.");
				}
				
				PKCS11KSEntry entry = new PKCS11KSEntry(certificate);
				PKCS11KSEntry pk_entry = privKeysById.get(certificate.getId());
				
				if (pk_entry != null)
				{
					entry.privateKey = pk_entry.privateKey;
					pk_entry.certificate = certificate;
				}
				
				this.entries.put(name,entry);
			}
			
			for (Integer id : privKeysById.keySet())
			{
				PKCS11KSEntry entry = privKeysById.get(id);
				
				if (entry.certificate != null) continue;
				
				String name = String.format("ID_%02X",id);
				
				this.entries.put(name,entry);
			}
		} catch (IOException e)
		{
			eventFailed(eventHandler,evCb,e);
			throw e;	
		} catch (CertificateException e)
		{
			eventFailed(eventHandler,evCb,e);
			throw e;	
		} catch (DestroyFailedException e)
		{
			eventFailed(eventHandler,evCb,e);
			throw new PKCS11Exception("destroy exception caught: ",e);
		}  catch (UnsupportedCallbackException e)
		{
			throw new PKCS11Exception("PasswordCallback is not supported",e);
		} 
	}

}
