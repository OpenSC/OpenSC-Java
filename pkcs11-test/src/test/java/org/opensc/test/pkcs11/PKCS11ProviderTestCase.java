package org.opensc.test.pkcs11;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.Random;

import org.opensc.pkcs11.PKCS11Provider;

import junit.framework.TestCase;

public abstract class PKCS11ProviderTestCase extends TestCase {

    protected PKCS11Provider provider;
    protected byte[] testData;

    public PKCS11ProviderTestCase() {
        super();
    }

    public void setUp() throws IOException {	
    	// Add provider "SunPKCS11-OpenSC"
    	String pkcs11_path;
    	
    	if (System.getProperty("os.name").contains("Windows"))
    		pkcs11_path = System.getenv("ProgramFiles")+"\\Smart Card Bundle\\opensc-pkcs11.dll";
    	else
    		pkcs11_path = "/usr/lib/opensc-pkcs11.so";
    		
        this.provider = new PKCS11Provider(pkcs11_path);
    	Security.addProvider(this.provider);
    			
    	Provider providers[] = Security.getProviders();
    	for (Provider p : providers)
    		System.out.println("Found provider: " + p.getName());
    	
        this.testData = new byte[199];
    	
    	Random random = new Random(System.currentTimeMillis());
    	
    	random.nextBytes(this.testData);
    }

    public void tearDown() {
        this.provider.cleanup();
        this.provider = null;
        this.testData = null;
    	Security.removeProvider("OpenSC-PKCS11");
    }

}