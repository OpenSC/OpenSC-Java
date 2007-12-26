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

import org.opensc.pkcs15.token.MFAcl;

/**
 * An implementation of an ACL for the master file on the token.
 * 
 * @author wglas
 */
public class MFAclImpl extends DFAclImpl implements MFAcl {

    private final int acExecute;
    private final int acAllocate;
    
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
     * @param acExecute
     * @param acAllocate
     */
    public MFAclImpl(int acLifeCycle, int acUpdate, int acAppend,
            int acActivate, int acDeactivate, int acDelete, int acAdmin,
            int acCreate, int acExecute, int acAllocate) {
        super(acLifeCycle, acUpdate, acAppend, acActivate, acDeactivate, acDelete,
                acAdmin,acCreate);
        this.acExecute = acExecute;
        this.acAllocate = acAllocate;
    }
    
    public MFAclImpl(MFAcl acl)
    {
        super(acl);
        this.acExecute = acl.getAcExecute();
        this.acAllocate = acl.getAcAllocate();
    }
            
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.MFAcl#getAcExecute()
     */
    public int getAcExecute() {
        return this.acExecute;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.MFAcl#getAcAllocate()
     */
    public int getAcAllocate() {
        return this.acAllocate;
    }
    
}
