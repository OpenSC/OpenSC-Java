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

import org.opensc.pkcs15.asn1.ISO7816ApplicationTemplate;
import org.opensc.pkcs15.token.Token;

/**
 * This interface describes a smart card application cf. to ISO7816.
 * 
 * The functionality in this interface is very terse, because the scope of
 * applications may range from PKI application to specialized applications for
 * public health care.
 * 
 * @author wglas
 */
public interface Application {

    /**
     * @return The application ID.
     */
    byte[] getAID();
    
    /**
     * @return The application template as stored inside the EF(DIR) object
     *         in the root path of a token.
     */
    public ISO7816ApplicationTemplate getApplicationTemplate();
    
    /**
     * @return The token on which this application resides.
     */
    public Token getToken();
    
}
