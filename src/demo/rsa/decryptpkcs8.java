package demo.rsa;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import sun.security.pkcs.PKCS8Key;



public class decryptpkcs8 {
	
	private static final String CLIENT_KEY_FILE = "src/demo/ssl/vkpem.PEM";
	//private static final String CLIENT_KEY_FILE = "src/demo/ssl/vk_p1.pem";
	private static final String CLIENT_KEY_PASSWORD  = "123456";
	
	private static PrivateKey readPrivateKeyPEM(File file, String password) throws IOException, GeneralSecurityException, OperatorCreationException, PKCSException {
	   try{
		   
		   Security.addProvider(new BouncyCastleProvider());
		   BouncyCastleProvider provider = new BouncyCastleProvider();
		   
		   
		   FileReader reader = new FileReader(file);
		   PEMParser parser = new PEMParser(reader);
	        Object object = parser.readObject();
	        if (object == null) {
	            throw new IllegalArgumentException("No key found in " + file);
	        }
	        
	        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(provider);
	        if (object instanceof PEMEncryptedKeyPair) {
	            // PKCS1 encrypted key
	        	System.out.println("PKCS#1");
	            PEMDecryptorProvider decryptionProvider = new JcePEMDecryptorProviderBuilder().setProvider("BC").build(password.toCharArray());
	            System.out.println("before decrypt");
	            PEMKeyPair keypair = ((PEMEncryptedKeyPair) object).decryptKeyPair(decryptionProvider);
	            System.out.println("decrypt ok");
	            return converter.getPrivateKey(keypair.getPrivateKeyInfo());
	        } else if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
	            // PKCS8 encrypted key
	        	System.out.println("PKCS#8");
	            InputDecryptorProvider decryptionProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(password.toCharArray());
	            System.out.println("before decrypt");
	            PrivateKeyInfo info = ((PKCS8EncryptedPrivateKeyInfo) object).decryptPrivateKeyInfo(decryptionProvider);
	            System.out.println("decrypt ok");
	            return converter.getPrivateKey(info);
	        } else if (object instanceof PEMKeyPair) {
	            // PKCS1 unencrypted key
	            return converter.getKeyPair((PEMKeyPair) object).getPrivate();
	        } else if (object instanceof PrivateKeyInfo) {
	            // PKCS8 unencrypted key
	            return converter.getPrivateKey((PrivateKeyInfo) object);
	        } else {
	            throw new UnsupportedOperationException("Unsupported PEM object: " + object.getClass().getSimpleName());
	           
	        }
	   }catch(Exception e){
		   e.printStackTrace();
		   return null;
	   }
	}
	
	public static PrivateKey loadEncryptedPrivateKey(String filename, String password) throws Exception {
		BouncyCastleProvider provider = new BouncyCastleProvider();
        FileReader fileReader = new FileReader(filename);
        PEMParser pemParser = new PEMParser(fileReader);
        PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) pemParser.readObject();
        PrivateKey key = new JcaPEMKeyConverter().setProvider(provider).getPrivateKey(
                pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(password.toCharArray())));

        return key;
}
	/*
	public static PrivateKey ParsePKCS8Key(String filename,String password)throws Exception
	{
		
		// If the provided InputStream is encrypted, we need a password to decrypt
		// it. If the InputStream is not encrypted, then the password is ignored
		// (can be null).  The InputStream can be DER (raw ASN.1) or PEM (base64).
		FileInputStream in = new FileInputStream(filename);
		PKCS8Key pkcs8 = new PKCS8Key(in,password.toCharArray());
		
		// If an unencrypted PKCS8 key was provided, then this actually returns
		// exactly what was originally passed in (with no changes).  If an OpenSSL
		// key was provided, it gets reformatted as PKCS #8 first, and so these
		// bytes will still be PKCS #8, not OpenSSL.
		byte[] decrypted = pkcs8.getDecryptedBytes();
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec( decrypted );
		// A Java PrivateKey object is born.
		PrivateKey pk = null;
		if ( pkcs8.isDSA() )
		{
		  pk = KeyFactory.getInstance( "DSA" ).generatePrivate( spec );
		}
		else if ( pkcs8.isRSA() )
		{
		  pk = KeyFactory.getInstance( "RSA" ).generatePrivate( spec );
		}

		// For lazier types:
		pk = pkcs8.getPrivateKey();
		return pk;
		
	}
	*/
	
	
	public static void main(String[] args) throws Exception  {
		
		//loadEncryptedPrivateKey(CLIENT_KEY_FILE,CLIENT_KEY_PASSWORD);
		
		File file = new File(CLIENT_KEY_FILE);
		readPrivateKeyPEM(file,CLIENT_KEY_PASSWORD);
		
		System.out.println("OK");
		
	}
	
}
