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
 * Created: 04.01.2009
 * 
 ***********************************************************/

package org.opensc.pkcs15.script;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * A command, which executes variable commands depending on the response of a command.
 * 
 * @author wglas
 */
public class SwitchCommand extends SimpleCommand {

    private static final long serialVersionUID = -8581673961206932426L;
    private Map<int[],Command> cases;
    
    /**
     * @param request The request to send to the card.
     * @param response The default response.
     * @param checkResponse Whether to throw an exception, when the default response differs.
     */
    public SwitchCommand(CommandAPDU request, int[] response,
            boolean checkResponse) {
        super(request, response, checkResponse);
    }

    /**
     * @param request The request to send to the card.
     * @param checkResponse Whether to throw an exception, when the response does singify success.
     */
    public SwitchCommand(CommandAPDU request, boolean checkResponse) {
        super(request, checkResponse);
    }

    /**
     * @return The cases depending on the expected response.
     */
    public Map<int[], Command> getCases() {
        return this.cases;
    }

    /**
     * @param cases The cases depending on the expected response.
     */
    public void setCases(Map<int[], Command> cases) {
        this.cases = cases;
    }

    /**
     * @param response The expected response.
     * @param cmd The command to execute in this case.
     */
    public void addCase(int[] response, Command cmd) {
        
        if (this.cases == null)
            this.cases = new HashMap<int[], Command>();
     
        this.cases.put(response,cmd);
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.script.SimpleCommand#checkResponse(javax.smartcardio.ResponseAPDU)
     */
    @Override
    protected Command checkResponse(ResponseAPDU resp) throws CardException {
       
        if (this.cases != null) {
            
            for (Entry<int[], Command> entry : this.cases.entrySet()) {
                
                if (doCheckResponse(resp.getBytes(),entry.getKey()))
                    return entry.getValue();
            }
        }
        
        return super.checkResponse(resp);
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.script.SimpleCommand#setNext(org.opensc.pkcs15.script.Command)
     */
    @Override
    public void setNext(Command next) {
      
        if (this.cases != null) {
            
            for (Command cmd : this.cases.values()) {
                
                while (cmd instanceof SimpleCommand) {
                 
                    SimpleCommand sc = (SimpleCommand) cmd;
                    
                    cmd = sc.getNext();
                    
                    if (cmd == null) {
                        sc.setNext(next);
                    }
                }
            }
        }
        
        super.setNext(next);
    }
}
