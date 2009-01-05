package test.org.opensc.pkcs15;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import junit.framework.AssertionFailedError;
import junit.framework.TestCase;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.opensc.pkcs15.AIDs;
import org.opensc.pkcs15.application.Application;
import org.opensc.pkcs15.application.ApplicationFactory;
import org.opensc.pkcs15.asn1.PKCS15AuthenticationObject;
import org.opensc.pkcs15.asn1.PKCS15Certificate;
import org.opensc.pkcs15.asn1.PKCS15Objects;
import org.opensc.pkcs15.asn1.PKCS15PrivateKey;
import org.opensc.pkcs15.asn1.PKCS15PublicKey;
import org.opensc.pkcs15.asn1.PKCS15RSAPublicKey;
import org.opensc.pkcs15.asn1.attr.CertificateObject;
import org.opensc.pkcs15.asn1.attr.PublicKeyObject;
import org.opensc.pkcs15.asn1.basic.TokenInfo;
import org.opensc.pkcs15.asn1.proxy.ReferenceProxy;
import org.opensc.pkcs15.token.PathHelper;
import org.opensc.pkcs15.token.Token;
import org.opensc.pkcs15.token.TokenContext;
import org.opensc.pkcs15.token.TokenFactory;
import org.opensc.pkcs15.token.TokenPath;
import org.opensc.pkcs15.util.Util;

public class TestSoftwareToken extends TestCase {
    
    private static Log log = LogFactory.getLog(TestSoftwareToken.class);
    
    private static TokenFactory tokenFactory = TokenFactory.newInstance();
    private static ApplicationFactory applicationFactory = ApplicationFactory.newInstance();
    
    private File tokenDir;
    private File tokenDir2;
    
    private ZipInputStream getTestZip() {
        return new ZipInputStream(TestSoftwareToken.class.getClassLoader().
                getResourceAsStream("test/org/opensc/pkcs15/test-ca.zip"));
    }
    
    protected void setUp() throws Exception {
        File targetDir = new File("target");
        targetDir.mkdir();

        this.tokenDir2 = new File(targetDir,"test-create");
        if (this.tokenDir2.exists())
            Util.rmdirRecursive(this.tokenDir2);
        this.tokenDir2.mkdir();
        
        this.tokenDir = new File(targetDir,"test-ca");
        if (this.tokenDir.exists())
            Util.rmdirRecursive(this.tokenDir);
        this.tokenDir.mkdir();
        
        ZipInputStream zis = this.getTestZip();           
        
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
                
                try {
                    byte[] buf = new byte[4096]; 
                    int n;
                
                    while ((n=zis.read(buf))>0) {
                        
                        fos.write(buf,0,n);
                    }
                }
                finally {
                    fos.close();
                }
            }
        }
        
        zis.close();
    }

    private void checkEquality(File baseDir) throws FileNotFoundException, IOException
    {
        ZipInputStream zis = this.getTestZip();           
        
        ZipEntry ze;
        
        while ((ze = zis.getNextEntry()) != null)
        {
            File file = new File(baseDir.getAbsoluteFile(),ze.getName());
            if (ze.isDirectory()) continue;
            
            log.info("checking entry ["+ze.getName()+"].");
            
            FileInputStream fis = new FileInputStream(file);
            
            int i = 0;
            int b1,b2;
            
            while ((b1 = zis.read()) != -1 && (b2 = fis.read()) != -1)
            {
                if (b1 != b2)
                    throw new AssertionFailedError("Byte ["+i+"] of EF ["+file+"] differs expected:[0x"+
                            Integer.toHexString(b1)+"], actual:[0x"+Integer.toHexString(b2)+"].");
                
                ++i;
            }
            fis.close();
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
  
        PathHelper.selectDF(token,new TokenPath(app.getApplicationTemplate().getPath()));
        
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
        
        PKCS15Certificate certificate =
            certificates.get(0);
        
        log.info("certificate="+certificate.getSpecificCertificateAttributes().getCertificateObject().getCertificate());
        
        PathHelper.selectDF(token,new TokenPath(app.getApplicationTemplate().getPath()));
        
        token.selectEF(0x5031);
        
        objs.writeInstance(token.writeEFData());
        
        assertTrue(objs.getAuthObjects() instanceof ReferenceProxy);
        ((ReferenceProxy<PKCS15AuthenticationObject>)objs.getAuthObjects()).updateEntity();
        
        assertTrue(objs.getPrivateKeys() instanceof ReferenceProxy);
        ((ReferenceProxy<PKCS15PrivateKey>)objs.getPrivateKeys()).updateEntity();
        
        assertTrue(pubKey.getSpecificPublicKeyAttributes().getPublicKeyObject() instanceof ReferenceProxy);
        ((ReferenceProxy<PublicKeyObject>)pubKey.getSpecificPublicKeyAttributes().getPublicKeyObject()).updateEntity();
            
        assertTrue(objs.getPublicKeys() instanceof ReferenceProxy);
        ((ReferenceProxy<PKCS15PublicKey>)objs.getPublicKeys()).updateEntity();
        
        assertTrue(objs.getCertificates() instanceof ReferenceProxy);
        ((ReferenceProxy<PKCS15Certificate>)objs.getCertificates()).updateEntity();
        
        assertTrue(certificate.getSpecificCertificateAttributes().getCertificateObject() instanceof ReferenceProxy);
        ((ReferenceProxy<CertificateObject>)certificate.getSpecificCertificateAttributes().getCertificateObject()).updateEntity();

        PathHelper.selectDF(token,new TokenPath(app.getApplicationTemplate().getPath()));
        
        token.selectEF(0x5032);
        
        ASN1InputStream ais = new ASN1InputStream(token.readEFData());
        TokenInfo tokenInfo = TokenInfo.getInstance(ais.readObject());
        
        ASN1OutputStream aos = new ASN1OutputStream(token.writeEFData());
        aos.writeObject(tokenInfo);
        aos.close();
        
        this.checkEquality(this.tokenDir);
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
