/***********************************************************
 * $Id$
 * 
 * Copyright (C) 2002-2006 ev-i Informationstechnologie GmbH
 *
 * Created: Dec 2, 2006
 *
 * Author: Wolfgang Glas/ev-i
 * 
 ***********************************************************/

package org.opensc.pkcs15.cardos.tools;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensc.pkcs15.util.Util;

/**
 * A class, which encpsulates the contents of a Siemens APDU script
 * file.
 * 
 * @author wglas
 */
public class CSFFile
{
    static private Log log = LogFactory.getLog(CSFFile.class);
    
    /**
     * A record in the csf file.
     * 
     * @author wglas
     */
    private static class Record
    {
        private CommandAPDU request;
        private byte[] response;
        
        public Record(CommandAPDU request, byte[] answer)
        {
            this.request = request;
            this.response = answer;
        }
        
        /**
         * @return the response
         */
        public byte[] getResponse()
        {
            return this.response;
        }
        /**
         * @return the request
         */
        public CommandAPDU getRequest()
        {
            return this.request;
        }
    }
    
    private List<Record> records;
    private Pattern assignmentPattern;
    
    private class Parser
    {
        private File file;
        private String lastLine;
        
        Parser (File file)
        {
            this.file = file;
            
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
            
            Matcher matcher = CSFFile.this.assignmentPattern.matcher(line);
            
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
        
        
        private void parse() throws IOException
        {
            InputStreamReader reader =
                new InputStreamReader(new FileInputStream(this.file),"ISO-8859-1");
        
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
                       
                    Record r = new Record(cmd,resp);
                    
                    CSFFile.this.records.add(r);
                    
                    log.debug("apdu = " + Util.asHex(r.getRequest().getBytes()));
                    
                    if (resp != null)
                        log.debug("resp = " + Util.asHex(resp));
                    
                    section = line;
                }
                else if ("[include]".equals(section))
                {
                    String line = this.readLine(reader);
                    
                    String kv[] = parseAssignment(line);
                    
                    if (!"file".equals(kv[0]))
                        throw new IOException("Invalid key ["+kv[0]+"] in section [include]");
                    
                    String relPath = kv[1].trim();;
                    
                    if (File.separatorChar != '\\')
                        relPath = relPath.replace('\\', File.separatorChar);
                    
                    File includeFile = new File(this.file.getParentFile(),relPath);
                    
                    log.info("Reading include file "+includeFile.getAbsolutePath());
                    
                    try {
                        Parser includeParser = new Parser(includeFile);
                        
                        includeParser.parse();
                    }
                    catch(FileNotFoundException e)
                    {
                        // Fix uppercase extensions, which actually represent lowercase
                        // extensions on a UNIX filesystem.
                        if (relPath.endsWith(".CSF"))
                        {
                            String fixedRelPath = relPath.substring(0,relPath.length()-4) + ".csf";
                            
                            includeFile = new File(this.file.getParentFile(),fixedRelPath);
                            
                            Parser includeParser = new Parser(includeFile);
                            
                            includeParser.parse();
                        }
                        else
                            throw e;
                    }
                    
                    section = this.readLine(reader);
                }
                else
                    throw new IOException("Unrecognized section "+section+" found.");
            }
        }
    }
  
    /**
     * Reads in a csf file from the filesystem and stores the APDU sequence
     * of the given file for later execution on a card using
     * {@link CSFFile#runScript(Card)}. 
     * 
     * @param file The abstract path of the file to load.
     * @throws IOException If the file is not a compliant CSF file.
     */
    public CSFFile(File file) throws IOException
    {
        this.records = new ArrayList<Record>();
        this.assignmentPattern = Pattern.compile("^([a-zA-Z][0-9a-zA-Z_]*)\\s*=(.*)$");
        
        Parser parser = new Parser(file);
        parser.parse();
    }
    
    static private boolean checkResponse(byte[] a, byte[] b)
    {
        if (b==null)
        {
            if (a.length != 2) return false;
            
            if (a[0] != (byte)0x90 || a[1] != 0x00) return false;
            return true;
        }
        
        if (a.length != b.length + 2) return false;
        
        if (a[b.length] != (byte)0x90 || a[b.length+1] != 0x00) return false;
        
        for (int i=0;i<b.length;++i)
            if (a[i] != b[i]) return false;
            
        return true;
    }
    
    /**
     * Execute the script of the loaded CSF file on a card reader.
     * 
     * @param channel A smart card connection channel.
     * @throws CardException 
     */
    public void runScript(CardChannel channel) throws CardException
    {
        for (Record record : this.records)
        {
            log.debug("Tranmitting APDU ["+record.getRequest()+"].");
            
            ResponseAPDU resp = channel.transmit(record.getRequest());
            
            log.debug("Got response ["+Util.asHex(resp.getBytes())+"].");
            
            if (!checkResponse(resp.getBytes(),record.getResponse()))
            {
                if (record.getResponse() != null)
                    log.warn("Response ["+Util.asHex(resp.getBytes())+
                            "] from card differs from expexted response ["+
                            Util.asHex(record.getResponse()) + "].");
                else
                    log.warn("Response ["+Util.asHex(resp.getBytes())+
                            "] from card does not signify success.");
            }
        }
    }
}
