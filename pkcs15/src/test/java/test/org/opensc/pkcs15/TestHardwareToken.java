package test.org.opensc.pkcs15;

import java.awt.Frame;
import java.awt.GraphicsConfiguration;
import java.awt.Label;
import java.awt.Point;
import java.awt.Rectangle;
import java.io.IOException;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;
import javax.smartcardio.CardTerminals.State;

import junit.framework.TestCase;

import org.opensc.pkcs15.AIDs;
import org.opensc.pkcs15.application.Application;
import org.opensc.pkcs15.application.ApplicationFactory;
import org.opensc.pkcs15.token.Token;
import org.opensc.pkcs15.token.TokenFactory;

public class TestHardwareToken extends TestCase {
    
    private static TerminalFactory terminalFactory = TerminalFactory.getDefault();
    private static TokenFactory tokenFactory = TokenFactory.newInstance();
    private static ApplicationFactory applicationFactory = ApplicationFactory.newInstance();
    
    private Card card;
    
    protected void setUp() throws Exception {
    
        CardTerminal terminal = null;
           
        CardTerminals terminals = terminalFactory.terminals();
            
        for (CardTerminal ct : terminals.list())
        {
            if (ct.isCardPresent())
            {
                terminal = ct;
                break;
            }
        }

        if (terminal==null)
        {
            Frame frame = new Frame("Enter card");
            
            Label label = new Label("Please insert smart card.");
            frame.add(label);
            frame.pack();
            frame.setVisible(true);
            GraphicsConfiguration gc = frame.getGraphicsConfiguration();
            Rectangle r = gc.getBounds();
            Point p = new Point((r.width-frame.getWidth())/2,(r.height-frame.getHeight())/2);
            
            frame.setLocation(p);
           
            terminals.waitForChange(60000);
            
            for (CardTerminal ct : terminals.list(State.CARD_INSERTION))
            {
                if (ct.isCardPresent())
                {
                    terminal = ct;
                    break;
                }
            }
            
            frame.setVisible(false);
            frame.dispose();
            if (terminal == null)
                throw new RuntimeException("No card inserted after 60 seconds.");
        }
    
        this.card = terminal.connect("*");
    }

    public void testApplicationFactory() throws IOException
    {
        Token token = tokenFactory.newHardwareToken(this.card);
        List<Application> apps = applicationFactory.listApplications(token);
        
        assertNotNull(apps);
        assertEquals(1,apps.size());
        assertEquals(AIDs.PKCS15_AID,apps.get(0).getAID());
    }
    
}
