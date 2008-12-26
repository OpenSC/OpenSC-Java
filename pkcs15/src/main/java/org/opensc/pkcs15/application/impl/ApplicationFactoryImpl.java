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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.opensc.pkcs15.AIDs;
import org.opensc.pkcs15.application.Application;
import org.opensc.pkcs15.application.ApplicationFactory;
import org.opensc.pkcs15.asn1.ISO7816ApplicationTemplate;
import org.opensc.pkcs15.asn1.ISO7816Applications;
import org.opensc.pkcs15.token.Token;
import org.opensc.pkcs15.token.TokenFileAcl;
import org.opensc.pkcs15.token.impl.EFAclImpl;
import org.opensc.pkcs15.util.Util;

/**
 * @author wglas
 *
 */
public class ApplicationFactoryImpl extends ApplicationFactory {

    public static final int DIR_PATH = 0x2F00;
    
    /**
     * Construct an existing application on a token.
     * 
     * Reimplement this method, if you like to add support for other application
     * IDs.
     * 
     * @param token The token on which the application has been found.
     * @param template The application template found in the DIR file.
     * @return The application object, if the AID of the template is recognized or null.
     * @throws IOException 
     */
    protected Application constructApplication(Token token, ISO7816ApplicationTemplate template) throws IOException
    {
        if (Arrays.equals(AIDs.PKCS15_AID,template.getAid()))
            return new PKCS15Application(token,template);
      
        return null;
    }
    
    /**
     * Construct a new application which will be lateron stored onto the token.
     * 
     * Reimplement this method, if you like to add support for other application
     * IDs.
     * 
     * @param token The token to which the new application will be bound.
     * @param aid The application ID.
     * @return The application object, if the application ID is recognized or null.
     */
    protected Application constructApplication(Token token, byte[] aid)
    {
        if (Arrays.equals(AIDs.PKCS15_AID,aid))
            return new PKCS15Application(token);
      
        return null;
    }
    
    /**
     * Read the applications directory from the token
     * 
     * @param token The token to read from.
     * @return the list of ISO7816 application record in the DIR objects or
     *         null if there is no DIR record on the token.
     * @throws IOException Upon errors.
     */
    protected ISO7816Applications readApplications(Token token) throws IOException
    {
        token.selectMF();
        if (token.selectEF(DIR_PATH) == null) return null;
        
        InputStream is = token.readEFData();
        
        ASN1InputStream ais = new ASN1InputStream(is);
        
        ISO7816Applications apps = new ISO7816Applications();
        
        ISO7816ApplicationTemplate template;
        
        while ((template=ISO7816ApplicationTemplate.getInstance(ais.readObject())) != null)
        {
            apps.addApplication(template);
        }
         
        ais.close();
        
        return apps;
    }
    
    /**
     * Write the applications directory to the token.
     * 
     * @param token The token to write to.
     * @param apps The list of application templates to write.
     * @throws IOException Upon errors.
     */
    protected void writeApplications(Token token, ISO7816Applications apps) throws IOException
    {
        token.selectMF();
        
        if (token.selectEF(DIR_PATH) == null) {
            token.createEF(DIR_PATH,
                    new EFAclImpl(TokenFileAcl.AC_ALWAYS,
                            TokenFileAcl.AC_ALWAYS,
                            TokenFileAcl.AC_ALWAYS,
                            TokenFileAcl.AC_ALWAYS,
                            TokenFileAcl.AC_ALWAYS,
                            TokenFileAcl.AC_ALWAYS,
                            TokenFileAcl.AC_ALWAYS,
                            TokenFileAcl.AC_ALWAYS,
                            TokenFileAcl.AC_ALWAYS
                            ));
           
            token.selectEF(DIR_PATH);
        }
        
        OutputStream os = token.writeEFData();
        
        ASN1OutputStream aos = new ASN1OutputStream(os);
        
        if (apps.getApplications() != null)
            for (ISO7816ApplicationTemplate template : apps.getApplications())
                aos.writeObject(template.toASN1Object());
            
        aos.write(0);
        aos.write(0);
        aos.close();
        
    }
    
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.application.ApplicationFactory#listApplications(org.opensc.pkcs15.token.Token)
     */
    @Override
    public List<Application> listApplications(Token token) throws IOException {
        
        ISO7816Applications applications = this.readApplications(token);
        
        if (applications == null || applications.getApplications() == null)
            return null;
            
        List<Application> ret =
            new ArrayList<Application>(applications.getApplications().size());
            
        for (ISO7816ApplicationTemplate template : applications.getApplications())
        {
            Application app = this.constructApplication(token,template);
            
            if (app != null)
                ret.add(app);
        }
            
        return ret;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.application.ApplicationFactory#newApplication(org.opensc.pkcs15.token.Token, byte[])
     */
    @Override
    public Application newApplication(Token token, byte[] aid)
            throws IOException {
        
        ISO7816Applications applications = this.readApplications(token);
        
        if (applications == null || applications.getApplications() == null)
            return null;
            
        for (ISO7816ApplicationTemplate template : applications.getApplications())
        {
            if (Arrays.equals(aid,template.getAid()))
            {
                Application app = this.constructApplication(token,template);
                
                if (app == null)
                    throw new IllegalArgumentException("Application with an unsupported application ID ["+
                            Util.asHex(aid)+"] has been requested from the token.");
                    
                return app;
            }
        }
            
        return null;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.application.ApplicationFactory#createApplication(org.opensc.pkcs15.token.Token, byte[])
     */
    @Override
    public Application createApplication(Token token, byte[] aid)
            throws IOException {
        
        Application app = this.constructApplication(token, aid);
        
        if (app == null)
            throw new IllegalArgumentException("An unsupported application ID ["+
                    Util.asHex(aid)+"] has been requested for creation.");
        
        ISO7816Applications applications = this.readApplications(token);
        
        if (applications == null)
            applications = new ISO7816Applications();
        
        applications.addApplication(app.getApplicationTemplate());
        
        this.writeApplications(token,applications);
        
        return app;
    }
}
