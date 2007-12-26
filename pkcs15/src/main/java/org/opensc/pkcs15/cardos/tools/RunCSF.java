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

import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;
import javax.smartcardio.CardTerminals.State;

/**
 * @author wglas
 */
public class RunCSF
{
    public static void listReaders(TerminalFactory terminalFactory) throws CardException
    {
        List<CardTerminal> readers = terminalFactory.terminals().list();
        
        for (int i=0 ; i<readers.size(); ++i)
            System.out.println("Reader "+i+": "+readers.get(i));
    }
    
    /**
     * @param args
     * @throws IOException 
     * @throws IOException 
     * @throws CardException 
     */
    public static void main(String[] args) throws IOException, CardException
    {
        TerminalFactory terminalFactory = TerminalFactory.getDefault();

        int iarg = 0;
        int ireader = -1;
        int timeout = 10000;
        
        while (iarg < args.length && args[iarg].charAt(0) == '-')
        {
            if ("--".equals(args[iarg]))
            {
                ++iarg;
                break;
            }
            else if ("-l".equals(args[iarg]))
            {
                listReaders(terminalFactory);
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
        
        try
        {
            CardTerminal terminal = null;
            if (ireader < 0)
            {
                System.out.println("timeout="+timeout);
                
                CardTerminals terminals = terminalFactory.terminals();
                
                for (CardTerminal ct : terminals.list())
                {
                    if (ct.isCardPresent())
                    {
                        terminal = ct;
                        break;
                    }
                }
                
                if (terminal == null)
                {
                    terminals.waitForChange(timeout);
                
                    for (CardTerminal ct : terminals.list(State.CARD_INSERTION))
                    {
                        if (ct.isCardPresent())
                        {
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
                
                boolean state = terminal.waitForCardPresent(timeout);
                
                if (!state)
                    throw new IOException("No card found in reader ["+terminal.getName()+"].");
            }
            
            card = terminal.connect("T=1");
            
            CardChannel channel = card.getBasicChannel();
            
            for (;iarg<args.length;++iarg)
            {
                File file = new File(args[iarg]);
                CSFFile csfFile = new CSFFile(file);
                csfFile.runScript(channel);
            }
        } finally
        {
            if (card != null)
                card.disconnect(false);
        }
    }

}
