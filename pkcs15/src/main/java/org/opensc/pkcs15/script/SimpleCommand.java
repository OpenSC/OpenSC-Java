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
 * Created: 29.12.2008
 * 
 ***********************************************************/

package org.opensc.pkcs15.script;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensc.pkcs15.util.Util;

/**
 * A simple APDU command with a successor and an expected result.
 * 
 * @author wglas
 */
public class SimpleCommand implements Command {

    private static final long serialVersionUID = -2415189277455553301L;

    private static final Log log = LogFactory.getLog(SimpleCommand.class);
    
    private final CommandAPDU request;
    private final int[] response;
    private final boolean checkResponse;
    private Command next;
    
    /**
     * @param request The APDU to be sent to the card.
     * @param response The expected response data, excluding the status.
     * @param checkResponse Whether to throw a {@link CardException} in {@link #execute(CardChannel)}
     *           when the card returns an unexpected response.
     */
    public SimpleCommand(CommandAPDU request, int[] response, boolean checkResponse) {
        super();
        this.request = request;
        this.response = response;
        this.checkResponse = checkResponse;
    }
    
    /**
     * @param request The APDU to be sent to the card.
     * @param checkResponse Whether to throw a {@link CardException} in {@link #execute(CardChannel)}
     *           when the card returns a response with a status other than <code>0x90 0x00</code>.
     */
    public SimpleCommand(CommandAPDU request, boolean checkResponse) {
        super();
        this.request = request;
        this.response = null;
        this.checkResponse = checkResponse;
    }
    
   /**
     * @return The next command to execute after this command or <code>null</code>, if
     *         this is the last command of a script.
     */
    public Command getNext() {
        return this.next;
    }

    /**
     * @param next The next command to execute after this command.
     */
    public void setNext(Command next) {
        this.next = next;
    }

    /**
     * @return the request to be sent to the card.
     */
    public CommandAPDU getRequest() {
        return this.request;
    }

    /**
     * @return the expected data portion of the expected response from the card.
     */
    public int[] getResponse() {
        return this.response;
    }

    /**
     * @return Whether to throw a {@link CardException} in {@link #execute(CardChannel)}, when
     *         the card return an unexpected result.
     */
    public boolean isCheckResponse() {
        return this.checkResponse;
    }

    /**
     * Check the response data against the expected response.
     * 
     * @param a The result of {@link ResponseAPDU#getBytes()}.
     * @return Whether the first <code>a.length-2</code> bytes are equal to
     *         {@link #getResponse()} and the last two bytes of <code>a</code>
     *         are equal to <code>0x90</code> and <code>0x00</code>.
     */
    protected static boolean doCheckResponse(byte[] a, int[] expected)
    {
        if (expected==null)
        {
            if (a.length != 2) return false;
            
            if (a[0] != (byte)0x90 || a[1] != 0x00) return false;
            return true;
        }
        
        if (a.length != expected.length + 2) return false;
        
        if (a[expected.length] != (byte)0x90 || a[expected.length+1] != 0x00) return false;
        
        for (int i=0;i<expected.length;++i) {

            int mask = (expected[i] & 0xff00) >> 8; 
            
            if ((a[i]&mask) != (expected[i]&mask)) return false;
        }
        
        return true;
    }

    protected Command checkResponse(ResponseAPDU resp) throws CardException {
        
        if (!doCheckResponse(resp.getBytes(),this.response))
        {
            String msg;
            
            if (this.getResponse() != null) {
            
                msg =
                    "Response ["+Util.asHex(resp.getBytes())+
                    "] from card differs from expected response ["+
                    Util.asHexMask(this.getResponse()) + "].";
                
            }
            else {
                msg=
                    "Response ["+Util.asHex(resp.getBytes())+
                    "] from card does not signify success.";
            }
            
            if (this.isCheckResponse())
                throw new CardException(msg);
            else
                log.warn(msg);
        }
       
        return this.next;
    }
    
    /* (non-Javadoc)
     * @see org.opensc.pkcs15.script.Command#execute(javax.smartcardio.CardChannel)
     */
    @Override
    public Command execute(CardChannel channel) throws CardException {
       
        log.debug("Tranmitting APDU ["+Util.asHex(this.getRequest().getBytes())+"].");
        
        ResponseAPDU resp = channel.transmit(this.getRequest());
        
        log.debug("Got response ["+Util.asHex(resp.getBytes())+"].");
        
        return this.checkResponse(resp);
    }

}
