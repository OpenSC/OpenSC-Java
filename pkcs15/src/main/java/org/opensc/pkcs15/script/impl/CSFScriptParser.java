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

package org.opensc.pkcs15.script.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.smartcardio.CommandAPDU;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensc.pkcs15.script.Command;
import org.opensc.pkcs15.script.ScriptParser;
import org.opensc.pkcs15.script.ScriptResource;
import org.opensc.pkcs15.script.SimpleCommand;
import org.opensc.pkcs15.util.Util;

/**
 * A parser for Siemens-style csf-files.
 * 
 * @author wglas
 */
public class CSFScriptParser implements ScriptParser {
    
    private static final Log log = LogFactory.getLog(CSFScriptParser.class);
    private static final Pattern assignmentPattern = Pattern.compile("^([a-zA-Z][0-9a-zA-Z_]*)\\s*=(.*)$");

    private static class Parser
    {
        private ScriptResource resource;
        private String lastLine;
        
        Parser (ScriptResource r)
        {
            this.resource = r;
            
            this.lastLine = null;
        }
        
        private String readLineRaw(Reader reader)  throws IOException
        {
            StringBuffer lineBuffer = new StringBuffer();
            
            int c;
            boolean blank = true;
            
            while((c=reader.read()) >= 0)
            {
                // strip off comments
                if (c == ';') break;
                if (c == '\n') break;
                if (c == '\r') continue;
                if (blank && !Character.isWhitespace(c))
                    blank=false;
                lineBuffer.append((char)c);     
            }
            
            if (c==';')
            {
                while((c=reader.read()) >= 0)
                    if (c == '\n') break;
            }
            
            if (blank)
            {
                if (c<0)
                    return null;
                else
                    return "";
            }
            else
            {
                return lineBuffer.toString();
            }
        }
        
        private String readLine(Reader reader) throws IOException
        {
            if (this.lastLine == null)
            {
                return null;
            }
            
            String ret;
            
            while (this.lastLine.length() <= 0)
            {
                this.lastLine = this.readLineRaw(reader);
                if (this.lastLine == null)
                    return null;
            }
            
            if (this.lastLine.charAt(0) == '[')
            {
                ret = this.lastLine;
                this.lastLine = this.readLineRaw(reader); 
            }
            else
            {
                ret = this.lastLine;
                this.lastLine = this.readLineRaw(reader);
                
                while (this.lastLine != null &&
                        this.lastLine.length() > 0 &&
                        Character.isWhitespace(this.lastLine.charAt(0)))
                {
                    ret = ret + this.lastLine;
                    this.lastLine = this.readLineRaw(reader);
                }
            }
 
            return ret.trim();
        }
        
        private String[] parseAssignment(String line) throws IOException
        {
            if (line == null)
                throw new IOException("Unexpected EOF after start of [include] section.");
            
            Matcher matcher = assignmentPattern.matcher(line);
            
            if (!matcher.matches())
                throw new IOException("Line ["+line+"] is not a valid assignment.");
            
            return new String[] { matcher.group(1), matcher.group(2) };  
        }
        
        private int hexDigit(char c) throws IOException
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            
            throw new IOException("Invalid hex digit ["+c+"] found.");
        }
        
        private int parseByte(String v) throws IOException
        {
            int i=0;
            
            while (i<v.length() && Character.isWhitespace(v.charAt(i))) ++i;
                
            if (i>=v.length()) throw new IOException("Invalid EOF parsing hex byte.");
            
            if (v.charAt(i) != '0')
                throw new IOException("No leading zero found in byte value ["+v+"].");
            
            if (++i>=v.length()) throw new IOException("Invalid EOF parsing hex byte.");
            
            int r = hexDigit(v.charAt(i)) << 4;
            
            if (++i>=v.length()) throw new IOException("Invalid EOF parsing hex byte.");
            
            r |= hexDigit(v.charAt(i));
            
            if (++i>=v.length()) throw new IOException("Invalid EOF parsing hex byte.");

            if (v.charAt(i) != 'h')
                throw new IOException("No trailing h found in byte value ["+v+"].");
            
            ++i;
            
            while (i<v.length() && Character.isWhitespace(v.charAt(i))) ++i;
            
            if (i<v.length())
                throw new IOException("Trailing garbage found in byte value ["+v+"].");
            
            return r;
        }
        
        private byte[] parseByteArray(String v) throws IOException
        {
            int i=0;
            
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            
            while (i<v.length())
            {
                while (i<v.length() && Character.isWhitespace(v.charAt(i))) ++i;
                
                if (i>=v.length()) break;
                
                if (v.charAt(i) != '0')
                    throw new IOException("No leading zero found in byte value ["+v+"].");
            
                if (++i>=v.length()) throw new IOException("Invalid EOF parsing hex byte.");
            
                int r = hexDigit(v.charAt(i)) << 4;
            
                if (++i>=v.length()) throw new IOException("Invalid EOF parsing hex byte.");
            
                r |= hexDigit(v.charAt(i));
            
                if (++i>=v.length()) throw new IOException("Invalid EOF parsing hex byte.");

                if (v.charAt(i) != 'h')
                    throw new IOException("No trailing h found in byte value ["+v+"].");
            
                ++i;
                
                bos.write(r);
            }
            
            return bos.toByteArray();
        }
        
        
        private SimpleCommand parse() throws IOException
        {
            InputStreamReader reader =
                new InputStreamReader(this.resource.asInputStream(),"ISO-8859-1");
        
            SimpleCommand ret = null;
            SimpleCommand simpleCommand = null;
            
            // initialize line buffer.
            this.lastLine = this.readLineRaw(reader);
            
            String section = this.readLine(reader);
            
            while (section != null)
            {
                if (section.charAt(0) != '[')
                    throw new IOException("Section header "+section+" does not start with an open bracket.");
                
                if (section.charAt(section.length()-1) != ']')
                    throw new IOException("Section header "+section+" does not end with a close bracket.");
                   
                if ("[reset]".equals(section))
                {
                    section = this.readLine(reader);
                }
                else if ("[transmit]".equals(section))
                {
                    String line = this.readLine(reader);
                    
                    int cla  =  -1;
                    int ins  =  -1;
                    int p1   =  -1;
                    int p2   =  -1;
                    byte[] data = null;
                    int le = -1;

                    byte[] resp = null;
                  
                    while (line != null && line.charAt(0) != '[')
                    {
                        String kv[] = parseAssignment(line);
                        
                        if ("cla".equals(kv[0]))
                            cla = this.parseByte(kv[1]);
                        else if ("ins".equals(kv[0]))
                            ins = this.parseByte(kv[1]);
                        else if ("p1".equals(kv[0]))
                            p1 = this.parseByte(kv[1]);
                        else if ("p2".equals(kv[0]))
                            p2 = this.parseByte(kv[1]);
                        else if ("le".equals(kv[0]))
                            le = this.parseByte(kv[1]);
                        else if ("data".equals(kv[0]))
                            data = this.parseByteArray(kv[1]);
                        else if ("resp".equals(kv[0]))
                            resp = this.parseByteArray(kv[1]);
                        else
                            throw new IOException("Invalid key ["+kv[0]+"] found in section [transmit].");
                        
                        line = this.readLine(reader);
                    }

                    if (cla < 0 || ins < 0 || p1 < 0 || p2 < 0)
                        throw new IOException("Missing cla,ins,p1 or p2 [transmit].");
                    
                    CommandAPDU cmd;
                    
                    if (data != null)
                        if (le >= 0)
                            cmd = new CommandAPDU(cla,ins,p1,p2,data,le);
                        else
                            cmd = new CommandAPDU(cla,ins,p1,p2,data);
                    else
                        if (le >= 0)
                            cmd = new CommandAPDU(cla,ins,p1,p2,le);
                        else
                            cmd = new CommandAPDU(cla,ins,p1,p2);
                       
                    SimpleCommand r = new SimpleCommand(cmd,resp,false);
                    
                    if (log.isDebugEnabled()) {
                        log.debug("apdu = " + Util.asHex(r.getRequest().getBytes()));
                    
                        if (resp != null)
                            log.debug("resp = " + Util.asHex(resp));
                    }
                    
                    if (ret == null)
                        ret = r;
                    
                    if (simpleCommand != null)
                        simpleCommand.setNext(r);
                    
                    simpleCommand = r;
                    
                    section = line;
                }
                else if ("[include]".equals(section))
                {
                    String line = this.readLine(reader);
                    
                    String kv[] = parseAssignment(line);
                    
                    if (!"file".equals(kv[0]))
                        throw new IOException("Invalid key ["+kv[0]+"] in section [include]");
                    
                    String relPath = kv[1].trim();
                    
                    relPath = relPath.replace('\\','/');
                    
                    ScriptResource includeFile = this.resource.openInclude(relPath);
                    
                    if (!includeFile.exists() && relPath.endsWith(".CSF")) {
                    
                        // Fix uppercase extensions, which actually represent lowercase
                        // extensions on a UNIX filesystem.
                        String fixedRelPath = relPath.substring(0,relPath.length()-4) + ".csf";
                        
                        includeFile = this.resource.openInclude(fixedRelPath);
                    }
                    
                    log.info("Reading include file ["+includeFile+"].");
                    
                    Parser includeParser = new Parser(includeFile);
                        
                    SimpleCommand r = includeParser.parse();
                   
                    if (ret == null)
                        ret = r;
                    
                    if (simpleCommand != null)
                        simpleCommand.setNext(r);
                    
                    simpleCommand = r;
                    
                    section = this.readLine(reader);
                }
                else
                    throw new IOException("Unrecognized section "+section+" found.");
            }
            return ret;
        }
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.script.ScriptParser#parseScript(org.opensc.pkcs15.script.ScriptResource)
     */
    @Override
    public Command parseScript(ScriptResource resource) throws IOException {
        
        Parser p = new Parser(resource);
        
        return p.parse();
    }
}
