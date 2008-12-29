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

package test.org.opensc.pkcs15;

import java.io.IOException;

import javax.smartcardio.CardException;

import org.opensc.pkcs15.script.Command;
import org.opensc.pkcs15.script.ScriptParser;
import org.opensc.pkcs15.script.ScriptParserFactory;
import org.opensc.pkcs15.script.ScriptResource;
import org.opensc.pkcs15.script.ScriptResourceFactory;

/**
 * Test Siemens' CSF sccripts.
 * 
 * @author wglas
 */
public class TestCSFScripts extends HardwareCardSupport {

    private static final ScriptResourceFactory scriptResourceFactory = ScriptResourceFactory.getInstance();
    private static final ScriptParserFactory scriptParserFactory = ScriptParserFactory.getInstance();
    
    private String getResourceBase() {
        
        return "file:/home/ev-i/Siemens/SmartCard/Unterlagen/CardOS_V4.3B/Packages_and_Release_Notes/V43B_CSF_Files_2005_05/Run_CSF";
    }
    
    public void testInitScripts() throws IOException, CardException {
        
        String resPath= this.getResourceBase() + "/Run_V43B_Erase_Profile_Default.csf";
        
        ScriptResource res = scriptResourceFactory.getScriptResource(resPath);
        
        ScriptParser csfParser = scriptParserFactory.getScriptParser("csf");
        
        Command cmd = csfParser.parseScript(res);
        
        cmd.execute(this.card.getBasicChannel());
    }
    
    
}
