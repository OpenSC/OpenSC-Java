/***********************************************************
 * $Id$
 * 
 * PKCS11 provider of the OpenSC project http://www.opensc-project.org
 *
 * Copyright (C) 2002-2006 ev-i Informationstechnologie GmbH
 *
 * Created: Jul 21, 2006
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

package org.opensc.pkcs11.wrap;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * @author wglas
 *
 * This class represents a public key as stored on the hardware token.
 */
public class PKCS11PublicKey extends PKCS11Key implements PublicKey
{
	/**
	 * To be changed upon class layout change.
	 */
	private static final long serialVersionUID = 7370269944653220123L;
	
	byte[] encoded;
	
	/**
	 * @param session The session to which this key belongs.
	 * @param handle The handle as returned by @see PKCS11Object#enumRawObjects(PKCS11Session, int).
	 * @throws PKCS11Exception
	 */
	protected PKCS11PublicKey(PKCS11Session session, int type, long handle)
			throws PKCS11Exception
	{
		super(session, type, handle);
		this.encoded = getRawAttribute(CKA_VALUE);
	}
	
	/**
	 * Fetches all private keys stored in the specified slot.
	 * 
	 * @param session The session of which to find the certificates. 
	 * @return The list of all private keys found in this slot.
	 * @throws PKCS11Exception Upon errors from the underlying PKCS11 module.
	 */
	public static List<PKCS11PublicKey> getPublicKeys(PKCS11Session session) throws PKCS11Exception
	{
		long[] handles = enumRawObjects(session,PKCS11Object.CKO_PUBLIC_KEY);
		
		List<PKCS11PublicKey> ret = new ArrayList<PKCS11PublicKey>(handles.length);
		
		for (int i = 0; i < handles.length; i++)
		{
			int keyType = PKCS11Object.getULongAttribute(session,handles[i],CKA_KEY_TYPE);

			PKCS11PublicKey key;
			
			switch (keyType)
			{
			case CKK_RSA:
				key = new PKCS11RSAPublicKey(session,keyType,handles[i]);
				break;
				
			case CKK_DSA:
				key = new PKCS11DSAPublicKey(session,keyType,handles[i]);
				break;
				
			default:
				key = new PKCS11PublicKey(session,keyType,handles[i]);
			}
			
			ret.add(key);
		}
		return ret;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	public byte[] getEncoded()
	{
		return this.encoded;
	}

}
