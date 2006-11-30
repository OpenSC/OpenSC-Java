/***********************************************************
 * $Id$
 * 
 * PKCS11 provider of the OpenSC project http://www.opensc-project.org
 *
 * Copyright (C) 2002-2006 ev-i Informationstechnologie GmbH
 *
 * Created: Jul 17, 2006
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

import javax.security.auth.DestroyFailedException;

import org.opensc.pkcs11.PKCS11Provider;
import org.opensc.util.DestroyableChild;

/**
 * @author wglas
 *
 * This class manages Objects like certificates or keys
 * stored on a PKCS11 device in a specific slot.
 */
public class PKCS11Object extends DestroyableChild implements PKCS11SessionChild
{
	/**
	 * The C handle of the provider.
	 */
	protected long pvh;
	
	/**
	 * The C handle of the slot.
	 */
	protected long shandle;

	/**
	 * The C handle of the session.
	 */
	protected long hsession;

	/**
	 * The C handle of the object.
	 */
	protected long handle;

	/**
	 * The Id of the object, i.e. the CKA_ID attribute value.
	 */
	private int id;
	
	/**
	 * The Id of the object, i.e. the CKA_ID attribute value.
	 */
	private String label;
	
	/*
	 * PKCS11 Class constants used for enumeration imported from pkcs11t.h
	 */
	static protected final int CKO_CERTIFICATE   =    0x00000001;
	static protected final int CKO_PUBLIC_KEY    =    0x00000002;
	static protected final int CKO_PRIVATE_KEY   =    0x00000003;
	static protected final int CKO_SECRET_KEY    =    0x00000004;
	
	/*
	 * PKCS11 Attribute constants used for attribute fetching imported from pkcs11t.h
	 */
	protected static final int CKA_CLASS              = 0x00000000;
	protected static final int CKA_TOKEN              = 0x00000001;
	protected static final int CKA_PRIVATE            = 0x00000002;
	protected static final int CKA_LABEL              = 0x00000003;
	protected static final int CKA_APPLICATION        = 0x00000010;
	protected static final int CKA_VALUE              = 0x00000011;
	
	/* CKA_OBJECT_ID is new for v2.10 */
	protected static final int CKA_OBJECT_ID          = 0x00000012;
	
	protected static final int CKA_CERTIFICATE_TYPE   = 0x00000080;
	protected static final int CKA_ISSUER             = 0x00000081;
	protected static final int CKA_SERIAL_NUMBER      = 0x00000082;
	
	/* CKA_AC_ISSUER, CKA_OWNER, and CKA_ATTR_TYPES are new 
	 * for v2.10 */
	protected static final int CKA_AC_ISSUER          = 0x00000083;
	protected static final int CKA_OWNER              = 0x00000084;
	protected static final int CKA_ATTR_TYPES         = 0x00000085;
	
	/* CKA_TRUSTED is new for v2.11 */
	protected static final int CKA_TRUSTED            = 0x00000086;
	
	protected static final int CKA_CERTIFICATE_CATEGORY       = 0x00000087;
	protected static final int CKA_JAVA_MIDP_SECURITY_DOMAIN  = 0x00000088;
	protected static final int CKA_URL                        = 0x00000089;
	protected static final int CKA_HASH_OF_SUBJECT_PUBLIC_KEY = 0x0000008a;
	protected static final int CKA_HASH_OF_ISSUER_PUBLIC_KEY  = 0x0000008b;
	protected static final int CKA_CHECK_VALUE                = 0x00000090;
	protected static final int CKA_KEY_TYPE           = 0x00000100;
	protected static final int CKA_SUBJECT            = 0x00000101;
	protected static final int CKA_ID                 = 0x00000102;
	protected static final int CKA_SENSITIVE          = 0x00000103;
	protected static final int CKA_ENCRYPT            = 0x00000104;
	protected static final int CKA_DECRYPT            = 0x00000105;
	protected static final int CKA_WRAP               = 0x00000106;
	protected static final int CKA_UNWRAP             = 0x00000107;
	protected static final int CKA_SIGN               = 0x00000108;
	protected static final int CKA_SIGN_RECOVER       = 0x00000109;
	protected static final int CKA_VERIFY             = 0x0000010A;
	protected static final int CKA_VERIFY_RECOVER     = 0x0000010B;
	protected static final int CKA_DERIVE             = 0x0000010C;
	protected static final int CKA_START_DATE         = 0x00000110;
	protected static final int CKA_END_DATE           = 0x00000111;
	protected static final int CKA_MODULUS            = 0x00000120;
	protected static final int CKA_MODULUS_BITS       = 0x00000121;
	protected static final int CKA_PUBLIC_EXPONENT    = 0x00000122;
	protected static final int CKA_PRIVATE_EXPONENT   = 0x00000123;
	protected static final int CKA_PRIME_1            = 0x00000124;
	protected static final int CKA_PRIME_2            = 0x00000125;
	protected static final int CKA_EXPONENT_1         = 0x00000126;
	protected static final int CKA_EXPONENT_2         = 0x00000127;
	protected static final int CKA_COEFFICIENT        = 0x00000128;
	protected static final int CKA_PRIME              = 0x00000130;
	protected static final int CKA_SUBPRIME           = 0x00000131;
	protected static final int CKA_BASE               = 0x00000132;
	
	/* CKA_PRIME_BITS and CKA_SUB_PRIME_BITS are new for v2.11 */
	protected static final int CKA_PRIME_BITS         = 0x00000133;
	protected static final int CKA_SUB_PRIME_BITS     = 0x00000134;
	
	protected static final int CKA_VALUE_BITS         = 0x00000160;
	protected static final int CKA_VALUE_LEN          = 0x00000161;

	protected static final int CKA_EXTRACTABLE        = 0x00000162;
	protected static final int CKA_LOCAL              = 0x00000163;
	protected static final int CKA_NEVER_EXTRACTABLE  = 0x00000164;
	protected static final int CKA_ALWAYS_SENSITIVE   = 0x00000165;

	/* internal native interface */
	private static native long[] enumObjectsNative(long pvh, long slot_handle, long hsession, int pkcs11_cls) throws PKCS11Exception;
	private static native byte[] getAttributeNative(long pvh, long slot_handle, long hsession, long handle, int att) throws PKCS11Exception;
	private static native int getULongAttributeNative(long pvh, long slot_handle, long hsession, long handle, int att) throws PKCS11Exception;
	private static native boolean getBooleanAttributeNative(long pvh, long slot_handle, long hsession, long handle, int att) throws PKCS11Exception;
	private static native PKCS11Mechanism[] getAllowedMechanismsNative(long pvh, long slot_handle, long hsession, long handle) throws PKCS11Exception;
	
	/**
	 * Just a small wrapper atround the native function.
	 * @param att The attribute type to receive.
	 * @return The raw value of the attribute.
	 * @throws PKCS11Exception Upon errors of the underlying PKCS#11 module.
	 */
	protected byte[] getRawAttribute(int att) throws PKCS11Exception
	{
		return  getAttributeNative(this.pvh,this.shandle,this.hsession,this.handle,att);
	}
	
	/**
	 * Just a small wrapper atround the native function.
	 * @param att The attribute type to receive.
	 * @return The 4-byte integer value of the attribute.
	 * @throws PKCS11Exception Upon errors of the underlying PKCS#11 module.
	 */
	protected int getULongAttribute(int att) throws PKCS11Exception
	{
		return  getULongAttributeNative(this.pvh,this.shandle,this.hsession,this.handle,att);
	}
	
	/**
	 * Just a small wrapper atround the native function.
	 * @param att The attribute type to receive.
	 * @return The 4-byte integer value of the attribute.
	 * @throws PKCS11Exception Upon errors of the underlying PKCS#11 module.
	 */
	protected static int getULongAttribute(PKCS11Session session, long handle, int att) throws PKCS11Exception
	{
		return  getULongAttributeNative(session.getPvh(),session.getSlotHandle(),session.getHandle(),handle,att);
	}
	
	/**
	 * Just a small wrapper atround the native function.
	 * @param att The attribute type to receive.
	 * @return The boolean value of the attribute.
	 * @throws PKCS11Exception Upon errors of the underlying PKCS#11 module.
	 */
	protected boolean getBooleanAttribute(int att) throws PKCS11Exception
	{
		return  getBooleanAttributeNative(this.pvh,this.shandle,this.hsession,this.handle,att);
	}
	
	/**
	 * Just a small wrapper atround the native function.
	 * @param att The attribute type to receive.
	 * @return The 4-byte integer value of the attribute.
	 * @throws PKCS11Exception Upon errors of the underlying PKCS#11 module.
	 */
	protected static boolean getBooleanAttribute(PKCS11Session session, long handle, int att) throws PKCS11Exception
	{
		return  getBooleanAttributeNative(session.getPvh(),session.getSlotHandle(),session.getHandle(),handle,att);
	}
	
	/**
	 * Just a small wrapper atround the native function.
	 * @param session The session for which to enumerate the objects.
	 * @param pkcs11_cls The object class to be seeked.
	 *        Should be one of the CKO_* constants
	 * @return The object handles of the retrieved objects,
	 *         which have to be passed to the constructor.
	 * @throws PKCS11Exception Upon errors of the underlying PKCS#11 module.
	 */
	protected static long[] enumRawObjects(PKCS11Session session, int pkcs11_cls) throws PKCS11Exception
	{
		return enumObjectsNative(session.getPvh(),session.getSlotHandle(),session.getHandle(),pkcs11_cls);
	}
	
	/**
	 * Protected contructor used by subclasses.
	 */
	protected PKCS11Object(PKCS11Session session, long handle) throws PKCS11Exception
	{
		super(session);
		this.pvh = session.getPvh();
		this.shandle = session.getSlotHandle();
		this.hsession = session.getHandle();
		this.handle = handle;
		
		try
		{
			byte[] utf8_id = getRawAttribute(CKA_ID);
			this.id = utf8_id[0];
			
			byte[] utf8_label = getRawAttribute(CKA_LABEL);
			this.label = new String(utf8_label,"UTF-8");
			
		} catch (UnsupportedEncodingException e)
		{
			throw new PKCS11Exception("Invalid encoding:",e);
		}
	}

	/**
	 * Just a small wrapper atround the native function.
	 * @return The allowed mechanism for this object.
	 * @throws PKCS11Exception Upon errors of the underlying PKCS#11 module.
	 */
	public PKCS11Mechanism[] getAllowedMechanisms() throws PKCS11Exception
	{
		return getAllowedMechanismsNative(this.pvh,this.shandle,this.hsession,this.handle);
	}
	
	/**
	 * @return The Id of this object.
	 */
	public int getId()
	{
		return this.id;
	}
	
	/**
	 * @return The label of this object.
	 */
	public String getLabel()
	{
		return this.label;
	}
	
	/**
	 * @return The underlying PKCS11 security provider.
	 *         This function throws a runtime exception, if destroy()
	 *         has been called before.
	 */
	public PKCS11Provider getProvider()
	{
		DestroyableChild session = (DestroyableChild)getParent();
		DestroyableChild slot = (DestroyableChild)session.getParent();
		return (PKCS11Provider)slot.getParent();
	}
	
	/* (non-Javadoc)
	 * @see org.opensc.pkcs11.wrap.PKCS11SessionChild#getPvh()
	 */
	public long getPvh()
	{
		return this.pvh;
	}
	
	/* (non-Javadoc)
	 * @see org.opensc.pkcs11.wrap.PKCS11SessionChild#getSlotHandle()
	 */
	public long getSlotHandle()
	{
		return this.shandle;
	}
	
	/* (non-Javadoc)
	 * @see org.opensc.pkcs11.wrap.PKCS11SessionChild#getSessionHandle()
	 */
	public long getSessionHandle()
	{
		return this.hsession;
	}

	/* (non-Javadoc)
	 * @see org.opensc.pkcs11.wrap.PKCS11SessionChild#getHandle()
	 */
	public long getHandle()
	{
		return this.handle;
	}

	/* (non-Javadoc)
	 * @see org.opensc.util.DestroyableChild#destroy()
	 */
	@Override
	public void destroy() throws DestroyFailedException
	{
		// just invalidate the handles.
        this.pvh = 0;
        this.shandle = 0;
        this.hsession = 0;
        this.handle = 0;
		super.destroy();
	}

}
