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

package org.opensc.pkcs15.application;

import java.io.IOException;
import java.util.List;

import javax.imageio.spi.ServiceRegistry;

import org.opensc.pkcs15.token.Token;

/**
 * A factory for application instances.
 * 
 * @author wglas
 */
public abstract class ApplicationFactory {

    /**
     * @return The first instance registered under the resource path
     *         <code>META-INF/serivces/org.opensc.pkcs15.application.ApplicationFactory</code>.
     *         
     * @see ServiceRegistry#lookupProviders(Class)
     */
    public static ApplicationFactory newInstance()
    {
        return ServiceRegistry.lookupProviders(ApplicationFactory.class).next();
    }
 
    /**
     * @param token A token instance.
     * @return The list of all supported applications on the token.
     * @throws IOException Upon errors.
     */
    public abstract List<Application> listApplications(Token token) throws IOException;
    
    /**
     * @param token A token instance.
     * @return The first application on the token matching the given AID.
     * @throws IOException Upon errors.
     */
    public abstract Application newApplication(Token token, byte[] aid) throws IOException;
    
    /**
     * @return A newly instantiated application, which is appended to the list of applications
     *         on the token.
     * @throws IOException Upon errors.
     */
    public abstract Application createApplication(Token token, byte[] aid) throws IOException;
    
}
