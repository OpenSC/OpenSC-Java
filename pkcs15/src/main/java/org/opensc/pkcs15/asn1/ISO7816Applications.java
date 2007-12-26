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
 * Created: 25.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1;

import java.util.ArrayList;
import java.util.List;

/**
 * A sequence of ISO7816ApplicationTaemplate as stored in the
 * EF(DIR) object in the root path of a token.
 * 
 * @author wglas
 */
public class ISO7816Applications {

    private List<ISO7816ApplicationTemplate> applications;
    
    /**
     * Default constructor.
     */
    public ISO7816Applications() {
    }

    /**
     * @return The list of applications found.
     */
    public List<ISO7816ApplicationTemplate> getApplications() {
        return this.applications;
    }

    /**
     * @param applications the applications to set
     */
    public void setApplications(List<ISO7816ApplicationTemplate> applications) {
        this.applications = applications;
    }
    
    /**
     * @param application the application to add
     */
    public void addApplication(ISO7816ApplicationTemplate application) {
        
        if (this.applications == null)
            this.applications = new ArrayList<ISO7816ApplicationTemplate>();
            
        this.applications.add(application);
    }
}
