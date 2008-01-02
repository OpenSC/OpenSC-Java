package test.org.opensc.pkcs15;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import junit.framework.TestCase;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.clazzes.util.io.IOUtil;
import org.opensc.pkcs15.AIDs;
import org.opensc.pkcs15.application.Application;
import org.opensc.pkcs15.application.ApplicationFactory;
import org.opensc.pkcs15.asn1.PKCS15AuthenticationObject;
import org.opensc.pkcs15.asn1.PKCS15Certificate;
import org.opensc.pkcs15.asn1.PKCS15Objects;
import org.opensc.pkcs15.asn1.PKCS15PrivateKey;
import org.opensc.pkcs15.asn1.PKCS15PublicKey;
import org.opensc.pkcs15.asn1.PKCS15RSAPublicKey;
import org.opensc.pkcs15.asn1.PKCS15X509Certificate;
import org.opensc.pkcs15.token.PathHelper;
import org.opensc.pkcs15.token.Token;
import org.opensc.pkcs15.token.TokenContext;
import org.opensc.pkcs15.token.TokenFactory;

public class TestSoftwareToken extends TestCase {
    
    private static Log log = LogFactory.getLog(TestSoftwareToken.class);
    
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
    
    public void testPKCS15Objects() throws IOException, CertificateParsingException
    {
        Token token = tokenFactory.newSoftwareToken(this.tokenDir);
        Application app = applicationFactory.newApplication(token,AIDs.PKCS15_AID);
  
        PathHelper.selectDF(token,app.getApplicationTemplate().getPath());
        
        token.selectEF(0x5031);
        
        PKCS15Objects objs = PKCS15Objects.readInstance(token.readEFData(),new TokenContext(token));
        
        assertNotNull(objs.getAuthObjects());
        assertNotNull(objs.getPrivateKeys());
        assertNotNull(objs.getPublicKeys());
        assertNotNull(objs.getCertificates());
        
        List<PKCS15AuthenticationObject> authObjects = objs.getAuthObjects().getSequence();
        assertEquals(1,authObjects.size());
        
        List<PKCS15PrivateKey> privateKeys = objs.getPrivateKeys().getSequence();
        assertEquals(1,privateKeys.size());
        
        List<PKCS15PublicKey> publicKeys = objs.getPublicKeys().getSequence();
        assertEquals(1,publicKeys.size());
        
        PKCS15RSAPublicKey pubKey = (PKCS15RSAPublicKey)(publicKeys.get(0));
        
        log.info("pubKey.modulus="+pubKey.getPublicRSAKeyAttributes().getValue().getModulus().toString(16));
        log.info("pubKey.exponent="+pubKey.getPublicRSAKeyAttributes().getValue().getPublicExponent().toString(16));
        log.info("pubKey.format="+pubKey.getPublicRSAKeyAttributes().getValue().getFormat());
        
        List<PKCS15Certificate> certificates = objs.getCertificates().getSequence();
        assertEquals(1,certificates.size());
        
        PKCS15X509Certificate certificate =
            (PKCS15X509Certificate)certificates.get(0);
        
        log.info("certificate="+certificate.getX509CertificateAttributes().getValue().getX509Certificate());
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
