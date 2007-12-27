package test.org.opensc.pkcs15;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import junit.framework.TestCase;

import org.clazzes.util.io.IOUtil;
import org.opensc.pkcs15.AIDs;
import org.opensc.pkcs15.application.Application;
import org.opensc.pkcs15.application.ApplicationFactory;
import org.opensc.pkcs15.token.Token;
import org.opensc.pkcs15.token.TokenFactory;

public class TestSoftwareToken extends TestCase {
    
    private static TokenFactory tokenFactory = TokenFactory.newInstance();
    private static ApplicationFactory applicationFactory = ApplicationFactory.newInstance();
    
    private File tokenDir;
    private File tokenDir2;
    
    static void rmDirForce(File dir)
    {
        File [] entries = dir.listFiles();
        
        for (File entry:entries)
        {
            if (entry.isDirectory()) {
                if (!entry.getName().equals(".") && !entry.getName().equals(".."))
                    rmDirForce(entry);
            }
            else {
                entry.delete();
            }
        }
        dir.delete();
    }

    protected void setUp() throws Exception {
        File targetDir = new File("target");
        targetDir.mkdir();

        this.tokenDir2 = new File(targetDir,"test-create");
        if (this.tokenDir2.exists())
            rmDirForce(this.tokenDir2);
        this.tokenDir2.mkdir();
        
        this.tokenDir = new File(targetDir,"test-ca");
        if (this.tokenDir.exists())
            rmDirForce(this.tokenDir);
        this.tokenDir.mkdir();
        
        ZipInputStream zis =
            new ZipInputStream(TestSoftwareToken.class.getClassLoader().
                    getResourceAsStream("test/org/opensc/pkcs15/test-ca.zip"));
        
        ZipEntry ze;
        
        while ((ze = zis.getNextEntry()) != null)
        {
            File file = new File(this.tokenDir,ze.getName());
            if (ze.isDirectory())
            {
                file.mkdirs();
            }
            else
            {
                FileOutputStream fos = new FileOutputStream(file);
                IOUtil.copyStreams(zis,fos);
            }
        }
        
        zis.close();
    }

    public void testApplicationFactory() throws IOException
    {
        Token token = tokenFactory.newSoftwareToken(this.tokenDir);
        List<Application> apps = applicationFactory.listApplications(token);
        
        assertNotNull(apps);
        assertEquals(1,apps.size());
        assertEquals(AIDs.PKCS15_AID,apps.get(0).getAID());
        
    }
    
    public void testApplicationCreation() throws IOException
    {
        Token token = tokenFactory.newSoftwareToken(this.tokenDir2);
        Application app = applicationFactory.createApplication(token,AIDs.PKCS15_AID);
        
        assertNotNull(app);
        
        List<Application> apps = applicationFactory.listApplications(token);
        
        assertNotNull(apps);
        assertEquals(1,apps.size());
        assertEquals(AIDs.PKCS15_AID,apps.get(0).getAID());
        
    }
    
}
