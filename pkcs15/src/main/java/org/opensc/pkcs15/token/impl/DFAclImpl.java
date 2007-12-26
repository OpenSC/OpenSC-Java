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

package org.opensc.pkcs15.token.impl;

import org.opensc.pkcs15.token.DFAcl;

/**
 * A dedicated file on the token.
 * 
 * @author wglas
 */
public class DFAclImpl extends TokenFileAclImpl implements DFAcl {

    private final int acLifeCycle;
    private final int acCreate;
    
    /**
     * @param path
     * @param acLifeCycle
     * @param acUpdate
     * @param acAppend
     * @param acActivate
     * @param acDeactivate
     * @param acDelete
     * @param acAdmin
     * @param acCreate
     */
    public DFAclImpl(int acLifeCycle, int acUpdate, int acAppend,
            int acActivate, int acDeactivate, int acDelete, int acAdmin, int acCreate) {
        super(acUpdate, acAppend, acActivate, acDeactivate, acDelete,
                acAdmin);
        this.acLifeCycle = acLifeCycle;
        this.acCreate = acCreate;
    }
    
    public DFAclImpl(DFAcl acl)
    {
        super(acl);
        this.acLifeCycle = acl.getAcLifeCycle();
        this.acCreate = acl.getAcCreate();
    }
            
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.DFAcl#getAcLifeCycle()
     */
    public int getAcLifeCycle() {
        return this.acLifeCycle;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.DFAcl#getAcCreate()
     */
    public int getAcCreate() {
        return this.acCreate;
    }
}
