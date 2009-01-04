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

package org.opensc.pkcs15.tool;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.List;
import java.util.Locale;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;
import javax.smartcardio.CardTerminals.State;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensc.pkcs15.script.Command;
import org.opensc.pkcs15.script.ScriptParser;
import org.opensc.pkcs15.script.ScriptParserFactory;
import org.opensc.pkcs15.script.ScriptResource;
import org.opensc.pkcs15.script.ScriptResourceFactory;

/**
 * A main program for accessing PKCS#15 functionality via the command line.
 * 
 * @author wglas
 */
public class Main
{
    private static final Log log = LogFactory.getLog(Main.class);
    
    private static final ScriptResourceFactory scriptResourceFactory = ScriptResourceFactory.getInstance();
    private static final ScriptParserFactory scriptParserFactory = ScriptParserFactory.getInstance();
    private static final TerminalFactory terminalFactory = TerminalFactory.getDefault();
    
    private static final String RUNSCRIPT_COMMAND = "runscript";
    private static final String SAVESCRIPT_COMMAND = "savescript";
    private static final String LISTREADERS_COMMAND = "listreaders";
    
    private static void listReaders() throws CardException
    {
        List<CardTerminal> readers = terminalFactory.terminals().list();
        
        for (int i=0 ; i<readers.size(); ++i)
            log.info("Reader "+i+": "+readers.get(i));
    }
    
    public static Card openCard(int ireader, long timeout) throws CardException, IOException {
        
        CardTerminal terminal = null;
        if (ireader < 0)
        {
            CardTerminals terminals = terminalFactory.terminals();
            
            for (CardTerminal ct : terminals.list())
            {
                if (log.isDebugEnabled())
                    log.debug("Checking for a card in terminal ["+ct.getName()+"].");
            
                if (ct.isCardPresent())
                {
                    log.info("Found a card in terminal ["+ct.getName()+"].");
                    terminal = ct;
                    break;
                }
            }
            
            if (terminal == null)
            {
                log.info("No card found in any terminal, waiting ["+timeout+"ms] for a card to appear...");
                
                terminals.waitForChange(timeout);
            
                for (CardTerminal ct : terminals.list(State.CARD_INSERTION))
                {
                    if (ct.isCardPresent())
                    {
                        log.info("A card has been inserted in terminal ["+ct.getName()+"].");
                        terminal = ct;
                        break;
                    }
                }
                
                if (terminal == null)
                    throw new IOException("No card found in any reader.");
            }
        }
        else
        {
            terminal = terminalFactory.terminals().list().get(ireader);
         
            log.info("Waiting ["+timeout+"ms] for a card to appear in terminal ["+terminal.getName()+"].");
            
            boolean state = terminal.waitForCardPresent(timeout);
            
            if (!state)
                throw new IOException("No card found in reader ["+terminal.getName()+"].");
            
            log.info("A card has been inserted in terminal ["+terminal.getName()+"].");
        }
        
        return terminal.connect("*");
    }
    
    private static void runScript(String[] args, int iarg, Card card) throws IOException, CardException {
        
        CardChannel channel = card.getBasicChannel();
        
        for (;iarg<args.length;++iarg)
        {
            ScriptResource res = scriptResourceFactory.getScriptResource(args[iarg]);
            
            int pos = args[iarg].lastIndexOf('.');
            
            if (pos < 0)
                throw new IOException("Unable to determine type of script ["+args[iarg]+"].");
            
            ScriptParser parser =
                scriptParserFactory.getScriptParser(args[iarg].substring(pos+1).toLowerCase(Locale.US));
            
            Command cmd = parser.parseScript(res);
            
            while (cmd != null)
                cmd = cmd.execute(channel);
        }
    }

    private static void saveScript(String[] args, int iarg) throws IOException {

        if (iarg != args.length-2)
            throw new IOException("usage: savescript [file|classpath]:<input> <output>.");
        
        ScriptResource res = scriptResourceFactory.getScriptResource(args[iarg]);
        
        int pos = args[iarg].lastIndexOf('.');
        
        if (pos < 0)
            throw new IOException("Unable to determine type of script ["+args[iarg]+"].");
        
        ScriptParser parser =
            scriptParserFactory.getScriptParser(args[iarg].substring(pos+1).toLowerCase(Locale.US));
        
        Command cmd = parser.parseScript(res);
       
        FileOutputStream fos = new FileOutputStream(args[iarg+1]);
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        
        oos.writeObject(cmd);
    }

    /**
     * @param args
     * @throws IOException 
     * @throws CardException 
     */
    public static void main(String[] args) throws IOException, CardException
    {
        String command = args[0];
        
        int iarg = 1;
        int ireader = -1;
        int timeout = 10000;
        
        while (iarg < args.length && args[iarg].charAt(0) == '-')
        {
            if ("--".equals(args[iarg]))
            {
                ++iarg;
                break;
            }
            
            else if ("-r".equals(args[iarg]))
            {
                ++iarg;
                
                ireader = Integer.valueOf(args[iarg]);
            }
            else if ("-t".equals(args[iarg]))
            {
                ++iarg;
                
                timeout = Integer.valueOf(args[iarg]);
            }
            
            ++iarg;
        }
        
        if (iarg >= args.length) return;
        
        Card card=null;
        int rv = 0;
        
        try
        {
            
            // if we need a card, open the card now.
            if (RUNSCRIPT_COMMAND.equals(command))
                card = openCard(ireader,timeout);
            
            // handle commands
            if (RUNSCRIPT_COMMAND.equals(command)) {
                runScript(args,iarg,card);
            } else if (SAVESCRIPT_COMMAND.equals(command)) {
                saveScript(args,iarg);
            } else if (LISTREADERS_COMMAND.equals(command)) {
                listReaders();
            } else {
                log.fatal("Unknown command ["+command+"] specified on the command line.");
                rv = 2;
            }
            
        } catch (Throwable e) {
          
            log.error("Error executing command ["+command+"]",e);
            rv = 1;
            
        } finally
        {
            if (card != null)
                card.disconnect(false);
        }
        System.exit(rv);
    }
}
