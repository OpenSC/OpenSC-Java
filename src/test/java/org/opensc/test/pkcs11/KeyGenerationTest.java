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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.RSAKeyGenParameterSpec;

import org.opensc.pkcs11.PKCS11LoadStoreParameter;
import org.opensc.pkcs11.spec.PKCS11RSAKeyPairGenParameterSpec;
import org.opensc.pkcs11.wrap.PKCS11Exception;
import org.opensc.pkcs11.wrap.PKCS11Mechanism;
import org.opensc.pkcs11.wrap.PKCS11NeRSAPrivateKey;
import org.opensc.pkcs11.wrap.PKCS11RSAPublicKey;

/**
 * @author wglas
 *
 */
public class KeyGenerationTest extends PKCS11ProviderTestCase {

    public void testRSAKeyPairGeneration() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, PKCS11Exception
    {
        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("RSA", super.provider);
        
        PKCS11RSAKeyPairGenParameterSpec params=
            new PKCS11RSAKeyPairGenParameterSpec(2048,RSAKeyGenParameterSpec.F4);
        
        params.setSigning(true);
        params.setVerify(true);
        params.setEncrypt(false);
        params.setDecrypt(false);
        params.setWrap(false);
        params.setUnwrap(false);
        
        params.setSensitive(true);
        params.setExtractable(false);
        
        PKCS11LoadStoreParameter lsp  = new PKCS11LoadStoreParameter();
        
        PINEntry pe = new PINEntry();
        
        lsp.setWaitForSlot(true);
        lsp.setSOProtectionCallback(pe);
        lsp.setProtectionCallback(pe);
        lsp.setEventHandler(pe);
        lsp.setWriteEnabled(true);
        
        params.setLoadStoreParameter(lsp);
        
        kpg.initialize(params);
        
        KeyPair kp = kpg.generateKeyPair();
        
        System.out.println("private.class="+kp.getPrivate().getClass());
        System.out.println("public.class="+kp.getPublic().getClass());
        
        PKCS11NeRSAPrivateKey priv =
            (PKCS11NeRSAPrivateKey)kp.getPrivate();
        
        System.out.println("priv.algorithm="+priv.getAlgorithm());
        System.out.println("priv.format="+priv.getFormat());
        System.out.println("priv.id="+priv.getId());
        System.out.println("priv.label="+priv.getLabel());
        System.out.println("priv.keyBits="+priv.getKeyBits());
        
        PKCS11Mechanism mechanisms[] = priv.getAllowedMechanisms();
        
        for (int i = 0; i < mechanisms.length; i++)
        {
            System.out.println("mecahnism["+i+"].type = "+mechanisms[i].getType()+" ("+mechanisms[i].getTypeName()+")");
            System.out.println("mechanism["+i+"].minKeySize = "+mechanisms[i].getMinKeySize());
            System.out.println("mechanism["+i+"].maxKeySize = "+mechanisms[i].getMaxKeySize());
            System.out.println("mechanism["+i+"].flags = "+mechanisms[i].getFlags());
        }

        PKCS11RSAPublicKey pub =
            (PKCS11RSAPublicKey)kp.getPublic();
        
        System.out.println("pub.algorithm="+pub.getAlgorithm());
        System.out.println("pub.format="+pub.getFormat());
        System.out.println("pub.id="+pub.getId());
        System.out.println("pub.label="+pub.getLabel());
        System.out.println("pub.keyBits="+pub.getKeyBits());
        System.out.println("pub.modlus="+pub.getModulus());
        
        mechanisms = pub.getAllowedMechanisms();
        
        for (int i = 0; i < mechanisms.length; i++)
        {
            System.out.println("mecahnism["+i+"].type = "+mechanisms[i].getType()+" ("+mechanisms[i].getTypeName()+")");
            System.out.println("mechanism["+i+"].minKeySize = "+mechanisms[i].getMinKeySize());
            System.out.println("mechanism["+i+"].maxKeySize = "+mechanisms[i].getMaxKeySize());
            System.out.println("mechanism["+i+"].flags = "+mechanisms[i].getFlags());
        }

    }
}
