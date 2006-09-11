/***********************************************************
 * $Id$
 * 
 * PKCS11 provider of the OpenSC project http://www.opensc-project.org
 *
 * Copyright (C) 2002-2006 ev-i Informationstechnologie GmbH
 *
 * Created: Sep 11, 2006
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

package org.opensc.pkcs11;

import java.security.KeyStore;

import javax.security.auth.callback.Callback;

/**
 * This callback is passed to a <code>CallbackHandlerProtection</code>,
 * which is passed as part of a <code>LoadStoreParameter</code> instance to
 * <code>KeyStore,load()</code>. An event callback is invoked each time
 * a defined event occurrs during the authentication process against a token.
 * 
 * @see java.security.KeyStore.CallbackHandlerProtection
 * @see javax.security.auth.callback.CallbackHandler
 * @see java.security.KeyStore.LoadStoreParameter
 * @see org.opensc.pkcs11.PKCS11LoadStoreParameter
 * @see KeyStore#load(java.security.KeyStore.LoadStoreParameter)
 * 
 * @author wglas
 */
public class PKCS11EventCallback implements Callback
{
	/**
	 * A dummy event for initializing an empty event callback.
	 */
	public static final int NO_EVENT               = 0;
	
	/**
	 * The initialization of the token failed.
	 */
	public static final int INITIALIZATION_FAILED  = 1;
	
	/**
	 * The provider is waiting for the insertion of a
	 * card into a token's slot.
	 */
	public static final int WAITING_FOR_CARD       = 2;
	
	/**
	 * The provider detected a failure while waiting for the insertion
	 * of a card into a token's slot.
	 */
	public static final int CARD_WAIT_FAILED       = 3;
	
	/**
	 * The provider is waiting for the entry of a PIN
	 * on the token. This event is invoked for tokens with
	 * a PINpad or another protected authentication path.
	 * 
	 * Tokens without a protected authentication path receive
	 * a <code>PasswordCallback</code> instead.
	 * 
	 * @see org.opensc.pkcs11.wrap.PKCS11Slot#hasTokenProtectedAuthPath()
	 * @see javax.security.auth.callback.PasswordCallback
	 */
	public static final int WAITING_FOR_HW_PIN     = 4;
	
	/**
	 * The provider is waiting for the entry of a PIN
	 * using a <code>PasswordCallback</code>.
	 * 
	 * @see org.opensc.pkcs11.wrap.PKCS11Slot#hasTokenProtectedAuthPath()
	 * @see javax.security.auth.callback.PasswordCallback
	 */
	public static final int WAITING_FOR_SW_PIN     = 5;
	
	/**
	 * The PIN entry failed either through a timeout or a
	 * hardware failure.
	 */
	public static final int PIN_ENTRY_FAILED       = 6;
	
	/**
	 * The PIN entry has been aborted by the user.
	 */
	public static final int PIN_ENTRY_ABORTED      = 7;
	
	/**
	 * The PIN entry suceeded and the validation process
	 * against the token starts.
	 */
	public static final int PIN_ENTRY_SUCEEDED     = 8;
	/**
	 * The presented PIN was wrong or the authentication
	 * failed due to a hardware error.
	 */
	public static final int AUHENTICATION_FAILED   = 9;
	
	/**
	 * The PIN has been successfully presented to the token and
	 * has been verified.
	 */
	public static final int AUHENTICATION_SUCEEDED = 10;
	
	private int event;
	
	/**
	 * Constructs an event callback signifying the given event.
	 *  
	 * @see PKCS11EventCallback#INITIALIZATION_FAILED
	 * @see PKCS11EventCallback#WAITING_FOR_CARD
	 * @see PKCS11EventCallback#WAITING_FOR_HW_PIN
	 * @see PKCS11EventCallback#PIN_ENTRY_FAILED
	 * @see PKCS11EventCallback#PIN_ENTRY_ABORTED
	 * @see PKCS11EventCallback#PIN_ENTRY_SUCEEDED
	 * @see PKCS11EventCallback#AUHENTICATION_FAILED
	 * @see PKCS11EventCallback#AUHENTICATION_SUCEEDED
	 */
	public PKCS11EventCallback(int event)
	{
		super();
		this.event = event;
	}

	/**
	 * @return Returns the event, which occurred during the authentication.
	 * 
	 * @see PKCS11EventCallback#INITIALIZATION_FAILED
	 * @see PKCS11EventCallback#WAITING_FOR_CARD
	 * @see PKCS11EventCallback#WAITING_FOR_HW_PIN
	 * @see PKCS11EventCallback#PIN_ENTRY_FAILED
	 * @see PKCS11EventCallback#PIN_ENTRY_ABORTED
	 * @see PKCS11EventCallback#PIN_ENTRY_SUCEEDED
	 * @see PKCS11EventCallback#AUHENTICATION_FAILED
	 * @see PKCS11EventCallback#AUHENTICATION_SUCEEDED
	 */
	public int getEvent()
	{
		return event;
	}

	/**
	 * @param event The event to set.
	 * 
	 * @see PKCS11EventCallback#INITIALIZATION_FAILED
	 * @see PKCS11EventCallback#WAITING_FOR_CARD
	 * @see PKCS11EventCallback#WAITING_FOR_HW_PIN
	 * @see PKCS11EventCallback#PIN_ENTRY_FAILED
	 * @see PKCS11EventCallback#PIN_ENTRY_ABORTED
	 * @see PKCS11EventCallback#PIN_ENTRY_SUCEEDED
	 * @see PKCS11EventCallback#AUHENTICATION_FAILED
	 * @see PKCS11EventCallback#AUHENTICATION_SUCEEDED
	 */
	public void setEvent(int event)
	{
		this.event = event;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString()
	{
		switch (this.event)
		{
		default:
		case NO_EVENT:               return "NO_EVENT";
		case INITIALIZATION_FAILED:  return "INITIALIZATION_FAILED";
		case WAITING_FOR_CARD:       return "WAITING_FOR_CARD";
		case CARD_WAIT_FAILED:       return "CARD_WAIT_FAILED";
		case WAITING_FOR_HW_PIN:     return "WAITING_FOR_HW_PIN";
		case WAITING_FOR_SW_PIN:     return "WAITING_FOR_SW_PIN";
		case AUHENTICATION_FAILED:   return "AUHENTICATION_FAILED";
		case AUHENTICATION_SUCEEDED: return "AUHENTICATION_SUCEEDED";
		case PIN_ENTRY_ABORTED:      return "PIN_ENTRY_ABORTED";
		case PIN_ENTRY_FAILED:       return "PIN_ENTRY_FAILED";
		case PIN_ENTRY_SUCEEDED:     return "PIN_ENTRY_SUCEEDED";
		}
	}

}
