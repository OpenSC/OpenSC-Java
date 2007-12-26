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
 * Created: 26.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15.application.impl;

import org.clazzes.util.lang.Util;
import org.opensc.pkcs15.AIDs;
import org.opensc.pkcs15.application.Application;
import org.opensc.pkcs15.asn1.ISO7816ApplicationTemplate;
import org.opensc.pkcs15.token.Token;

/**
 * @author wglas
 *
 */
public class PKCS15Application implements Application {
    
    private ISO7816ApplicationTemplate template;
    private Token token;
    
    private static final byte[] DEFAULT_PATH = new byte[] { 0x3F, 0x00, 0x50, 0x15 };
    
    /**
     * default constructor.
     */
    PKCS15Application(Token token)
    {
        this.token = token;
        this.template = new ISO7816ApplicationTemplate();
        this.template.setAid(AIDs.PKCS15_AID);
        this.template.setDescription("OpenSC JAVA");
        this.template.setPath(DEFAULT_PATH);
    }
    
    /**
     * default constructor.
     */
    PKCS15Application(Token token, ISO7816ApplicationTemplate template)
    {
        if (template == null)
            throw new IllegalArgumentException("PKCS15Application instantiated with template == null.");
            
        if (template.getAid() == null)
            throw new IllegalArgumentException("PKCS15Application instantiated with template.aid == null.");
            
        if (!Util.equals(AIDs.PKCS15_AID,template.getAid()))
            throw new IllegalArgumentException("PKCS15Application instantiated with invalid AID in template.");
            
        this.template = template;
        this.token = token;
    }
    
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.application.Application#getAID()
     */
    @Override
    public byte[] getAID() {
        
        return AIDs.PKCS15_AID;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.application.Application#getApplicationTEmplate()
     */
    @Override
    public ISO7816ApplicationTemplate getApplicationTemplate() {
        
        return this.template;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.application.Application#getToken()
     */
    @Override
    public Token getToken() {
        
        return this.token;
    }

 
}
