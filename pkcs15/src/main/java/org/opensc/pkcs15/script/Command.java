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
 * Created: 27.12.2008
 * 
 ***********************************************************/

package org.opensc.pkcs15.script;

import java.io.Serializable;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;

/**
 * A command, which may be executed on a smart card channel.
 * 
 * @author wglas
 */
public interface Command extends Serializable {

    /**
     * Execute this command on the given connected smart card channel. 
     * 
     * @param channel The channel to which we send the command.
     * @return The next command in line to execute or null, if the execution has terminated.
     * @throws CardException upon errors.
     */
    public Command execute(CardChannel channel) throws CardException; 
}
