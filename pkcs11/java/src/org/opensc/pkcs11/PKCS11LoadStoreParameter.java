package org.opensc.pkcs11;

import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;

/**
 * An instance of this class should be passed to the function <tt>KeyStore.load()</tt>
 * in order to configure PKCS11 store loading with parameters appropriate
 * for cyrptographic tokens.
 * 
 * @see java.security.KeyStore#load(java.security.KeyStore.LoadStoreParameter)
 * @author wglas
 */
public class PKCS11LoadStoreParameter implements LoadStoreParameter
{
	ProtectionParameter protectionParameter;
	ProtectionParameter SOProtectionParameter;
	boolean waitForSlot;
	Long slotId;
	boolean writeEnabled;
		
	/**
	 * Constructs a PKCS11LoadStoreParameter instance using default settings.
	 * 
	 * No protection parameters are set, the slot ID ist set to null and
	 * <tt>KeyStore.load()</tt>
	 * does not not wait for a token insertion, if no token is present.
	 */
	public PKCS11LoadStoreParameter()
	{
		this.protectionParameter   = null;
		this.SOProtectionParameter = null;
		this.waitForSlot           = false;
		this.slotId                = null;
		this.writeEnabled          = false;
	}
	
	/* (non-Javadoc)
	 * @see java.security.KeyStore$LoadStoreParameter#getProtectionParameter()
	 */
	public ProtectionParameter getProtectionParameter()
	{
		return protectionParameter;
	}
	
	/**
	 * @return The protection parameter of the security officer,
	 *         which might be used in order to store a certificate on the
	 *         token.
	 */
	public ProtectionParameter getSOProtectionParameter()
	{
		return SOProtectionParameter;
	}

	/**
	 * @param protectionParameter The security officer protection parameter to
	 *                            be used. A SO protection parameter is used,
	 *                            when the token is opened in read/write mode.
	 *                            
	 * @see java.security.KeyStore.PasswordProtection
	 * @see java.security.KeyStore.CallbackHandlerProtection
	 * @see javax.security.auth.callback.PasswordCallback
	 * @see PKCS11EventCallback
	 */
	public void setSOProtectionParameter(ProtectionParameter protectionParameter)
	{
		SOProtectionParameter = protectionParameter;
	}

	/**
	 * @param protectionParameter The protectionParameter for the normal user to set
	 *                            A protection parameter for a normal user
	 *                            is needed for signing as well as for listing 
	 *                            private keys on the token.
	 *                            
	 * @see java.security.KeyStore.PasswordProtection
	 * @see java.security.KeyStore.CallbackHandlerProtection
	 * @see javax.security.auth.callback.PasswordCallback
	 * @see PKCS11EventCallback
	 */
	public void setProtectionParameter(ProtectionParameter protectionParameter)
	{
		this.protectionParameter = protectionParameter;
	}
	
	/**
	 * @return Returns the ID of the slot to be opened.
	 */
	public Long getSlotId()
	{
		return slotId;
	}

	/**
	 * @param slotId Set the ID of the slot to be opened.
	 *               If set to null, the KeyStore opens the first slot
	 *               with a present token.
	 */
	public void setSlotId(Long slotId)
	{
		this.slotId = slotId;
	}

	/**
	 * @return Returns, whether the KeyStore should wait for a token to be inserted
	 *         if no token is found.
	 */
	public boolean isWaitForSlot()
	{
		return waitForSlot;
	}

	/**
	 * @param waitForSlot Set, whether the KeyStore should wait for a token
	 *                    to be inserted if no token is found.
	 */
	public void setWaitForSlot(boolean waitForSlot)
	{
		this.waitForSlot = waitForSlot;
	}

	/**
	 * @return Returns, whether the token should be opened in read/write mode instead
	 *         of read-only mode.
	 */
	public boolean isWriteEnabled()
	{
		return writeEnabled;
	}

	/**
	 * @param writeEnabled Set, whether the token should be opened in read/write mode
	 *                     instead of read-only mode.
	 */
	public void setWriteEnabled(boolean writeEnabled)
	{
		this.writeEnabled = writeEnabled;
	}
}
