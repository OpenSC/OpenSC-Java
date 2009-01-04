package test.org.opensc.pkcs15;

import java.io.IOException;
import java.util.List;



import org.opensc.pkcs15.AIDs;
import org.opensc.pkcs15.application.Application;
import org.opensc.pkcs15.application.ApplicationFactory;
import org.opensc.pkcs15.token.Token;
import org.opensc.pkcs15.token.TokenFactory;

public class TestHardwareToken extends HardwareCardSupport {
    
    private static TokenFactory tokenFactory = TokenFactory.newInstance();
    private static ApplicationFactory applicationFactory = ApplicationFactory.newInstance();
    
    public void testApplicationFactory() throws IOException
    {
        Token token = tokenFactory.newHardwareToken(this.card);
        List<Application> apps = applicationFactory.listApplications(token);
        
        assertNotNull(apps);
        assertEquals(1,apps.size());
        assertEquals(AIDs.PKCS15_AID,apps.get(0).getAID());
    }
    
    public void testApplicationCreation() throws IOException
    {
        Token token = tokenFactory.newHardwareToken(this.card);
        
        token.reset();
        
        Application app = applicationFactory.createApplication(token,AIDs.PKCS15_AID);
        
        assertNotNull(app);
        
        List<Application> apps = applicationFactory.listApplications(token);
        
        assertNotNull(apps);
        assertEquals(1,apps.size());
        assertEquals(AIDs.PKCS15_AID,apps.get(0).getAID());
        
    }
    
}
