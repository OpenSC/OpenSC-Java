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

package org.opensc.pkcs11.wrap;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.DestroyFailedException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensc.pkcs11.PKCS11Provider;
import org.opensc.util.DestroyableHolder;

public class PKCS11Slot extends DestroyableHolder
{
	static private final Log log = LogFactory.getLog(PKCS11Slot.class);

	/**
	 * The ID of the token.
	 */
	private long id;
	
	/**
	 * The C handle of the provider.
	 */
	private long pvh;
	
	/**
	 * The C handle of the slot.
	 */
	private long handle;
	
	private native long initSlotNative(long pvh, long id) throws PKCS11Exception;
	private native void destroySlotNative(long pvh, long handle) throws DestroyFailedException;
	
	/**
	 * This contructor constructs an instance of an individual slot.
	 * The slots a usually label starting with an Id of 0 and onwards.
	 * So, if you have just one device attached to your computer you
	 * should usually done by calling new PKCS11Slot(provider,0).
	 * 
	 * @param id The Id of the slot.
	 * @throws PKCS11Exception Upon errors when retrieving the slot information.
	 */
	public PKCS11Slot(PKCS11Provider provider, long id) throws PKCS11Exception
	{
		super(provider);
		this.id = id;
		this.pvh = provider.getPkcs11ModuleHandle();
		this.handle = initSlotNative(this.pvh,id);
	}
	
	private static native long[] enumerateSlotsNative(long pvh) throws PKCS11Exception;

	/**
	 * Enumeraate all available slots of a given PKCS11 provider.
	 * 
	 * @param provider The PKCS11 provider to retrieve the slots for.
	 * @return A list of all available slots.
	 * @throws PKCS11Exception Upon errors when retrieving the slot information.
	 */
	public static List<PKCS11Slot> enumerateSlots(PKCS11Provider provider) throws PKCS11Exception
	{
		long[] ids = enumerateSlotsNative(provider.getPkcs11ModuleHandle());
		
		List<PKCS11Slot> ret = new ArrayList<PKCS11Slot> (ids.length);
		
		for (int i = 0; i < ids.length; i++)
		{
			ret.add(new PKCS11Slot(provider, ids[i]));
		}
		return ret;
	}
	
	private static native long waitForSlotNative(long pvh) throws PKCS11Exception;

	/**
	 * Enumerate all available slots of a given PKCS11 provider.
	 * 
	 * @param provider The PKCS11 provider to retrieve the slots for.
	 * @return A list of all available slots.
	 * @throws PKCS11Exception Upon errors when retrieving the slot information.
	 */
	public static PKCS11Slot waitForSlot(PKCS11Provider provider)
			throws PKCS11Exception
	{
		long id = -1;

		try
		{
			id = waitForSlotNative(provider.getPkcs11ModuleHandle());
		} catch (PKCS11Exception e)
		{
			if (e.getErrorCode() == PKCS11Exception.CKR_FUNCTION_NOT_SUPPORTED)
				try
				{
					PKCS11Slot ret = null;

					do
					{
						Thread.sleep(1000);

						List<PKCS11Slot> slots = enumerateSlots(provider);

						for (PKCS11Slot slot : slots)
						{
							if (ret == null && slot.isTokenPresent())
								ret = slot;
							else
								try
								{
									slot.destroy();
								} catch (DestroyFailedException e1)
								{
									log.warn("destroy error while waiting for slot:",
											e1);
								}
						}
					} while (ret == null);
					
					return ret;
					
				} catch (InterruptedException e1)
				{
					throw new PKCS11Exception(
							PKCS11Exception.CKR_FUNCTION_CANCELED,
							"The operation has been interrupted.");
				}
			else
			{
				throw e;
			}
		}

		return new PKCS11Slot(provider, id);
	}
	
	private native boolean isTokenPresentNative(long pvh, long handle) throws PKCS11Exception;
	
	/**
	 * @return Whether a token is present in this slot.
	 */
	public boolean isTokenPresent() throws PKCS11Exception
	{
		return isTokenPresentNative(pvh,handle);
	}
	
	private native boolean isRemovableDeviceNative(long pvh, long handle) throws PKCS11Exception;
	
	/**
	 * @return Whether a token is present in this slot.
	 */
	public boolean isRemovableDevice() throws PKCS11Exception
	{
		return isRemovableDeviceNative(pvh,handle);
	}
	
	private native boolean isHardwareDeviceNative(long pvh, long handle) throws PKCS11Exception;
	
	/**
	 * @return Whether a token is present in this slot.
	 */
	public boolean isHardwareDevice() throws PKCS11Exception
	{
		return isHardwareDeviceNative(pvh,handle);
	}
	
	private native byte[] getManufaturerNative(long pvh, long handle) throws PKCS11Exception;
	
	/**
	 * @return The manufacturer of the slot.
	 */
	public String getManufaturer() throws PKCS11Exception
	{
		try
		{
			return new String(getManufaturerNative(pvh,handle),"UTF-8");
		} catch (UnsupportedEncodingException e)
		{
			return null;
		}
	}
	
	private native byte[] getDescriptionNative(long pvh, long handle) throws PKCS11Exception;
	
	/**
	 * @return A description of the slot.
	 */
	public String getDescription() throws PKCS11Exception
	{
		try
		{
			return new String(getDescriptionNative(pvh,handle),"UTF-8");
		} catch (UnsupportedEncodingException e)
		{
			return null;
		}
	}
	
	private native double getHardwareVersionNative(long pvh, long handle) throws PKCS11Exception;
	
	/**
	 * @return The hardware verion of the slot.
	 */
	public double getHardwareVersion() throws PKCS11Exception
	{
		return getHardwareVersionNative(pvh,handle);
	}
	
	private native double getFirmwareVersionNative(long pvh, long handle) throws PKCS11Exception;
	
	/**
	 * @return The Firmware verion of the slot.
	 */
	public double getFirmwareVersion() throws PKCS11Exception
	{
		return getFirmwareVersionNative(pvh,handle);
	}
	
	private native PKCS11Mechanism[] getMechanismsNative(long pvh, long handle) throws PKCS11Exception;
	
	/**
	 * @return A list of mechanisms supported by this slot.
	 * @throws PKCS11Exception
	 */
	public PKCS11Mechanism[] getMechanisms() throws PKCS11Exception
	{
		return getMechanismsNative(pvh,handle);
	}
	
	/**
	 * @return Returns the id of this slot.
	 */
	public long getId()
	{
		return id;
	}

	/* (non-Javadoc)
	 * @see org.opensc.pkcs11.util.DestroyableChild#destroy()
	 */
	@Override
	public void destroy() throws DestroyFailedException
	{
		super.destroy();

		if (handle != 0)
		{
			destroySlotNative(pvh,handle);
			handle = 0;
		}
	}
	
	/**
	 * @return Returns the C handle of the underlying provider.
	 */
	protected long getPvh()
	{
		return pvh;
	}
	
	/**
	 * @return Returns the C handle of the slot.
	 */
	protected long getHandle()
	{
		return handle;
	}
	
}
