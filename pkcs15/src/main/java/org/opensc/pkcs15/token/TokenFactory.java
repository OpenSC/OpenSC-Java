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

package org.opensc.pkcs15.token;

import java.io.File;
import java.io.IOException;

import javax.imageio.spi.ServiceRegistry;
import javax.smartcardio.Card;

/**
 * A factory for token instances.
 * 
 * @author wglas
 */
public abstract class TokenFactory {

    /**
     * @return The first instance registered under the resource path
     *         <code>META-INF/serivces/org.opensc.pkcs15.token.TokenFactory</code>.
     *         
     * @see ServiceRegistry#lookupProviders(Class)
     */
    public static TokenFactory newInstance()
    {
        return ServiceRegistry.lookupProviders(TokenFactory.class).next();
    }
 
    /**
     * @param card A connected smart card.
     * @return The token instance depending on the ATR of the supplied card.
     * @throws IOException Upon errors.
     */
    public abstract Token newHardwareToken(Card card) throws IOException;
    
    /**
     * @param file A zip file or a directory containing the token infrastructure.
     * @return A token instance for the software token.
     * @throws IOException Upon errors.
     */
    public abstract Token newSoftwareToken(File file) throws IOException;    
    
}
