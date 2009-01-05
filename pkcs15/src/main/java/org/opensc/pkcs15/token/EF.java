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

package org.opensc.pkcs15.token;

/**
 * An elementary file on the token.
 * 
 * @author wglas
 */
public class EF extends TokenFile implements EFAcl {

    private final int acRead;
    private final int acIncrease;
    private final int acDecrease;
    
    /**
     * @param path
     * @param acRead
     * @param acUpdate
     * @param acAppend
     * @param acDeactivate
     * @param acActivate
     * @param acDelete
     * @param acAdmin
     */
    public EF(TokenPath path, long size,
            int acRead, int acUpdate, int acAppend,
            int acDeactivate, int acActivate, int acDelete, int acAdmin,
            int acIncrease, int acDecrease) {
        super(path, size, acUpdate, acAppend, acDeactivate, acActivate, acDelete,
                acAdmin);
        this.acRead = acRead;
        this.acIncrease = acIncrease;
        this.acDecrease = acDecrease;
    }
    
    public EF(TokenPath path, long size, EFAcl acl)
    {
        super(path,size,acl);
        this.acRead = acl.getAcRead();
        this.acIncrease = acl.getAcIncrease();
        this.acDecrease = acl.getAcDecrease();
    }
    
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.TokenFile#accept(org.opensc.pkcs15.token.TokenFileVisitor)
     */
    @Override
    void accept(TokenFileVisitor visitor) {
        visitor.visit(this);
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.EFAcl#getAcRead()
     */
    public int getAcRead() {
        return this.acRead;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.EFAcl#getAcIncrease()
     */
    public int getAcIncrease() {
        return this.acIncrease;
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.EFAcl#getAcDecrease()
     */
    public int getAcDecrease() {
        return this.acDecrease;
    }
}
