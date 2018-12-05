package demo.ssl;

/**
 * Utility class to read encrypted PEM files and generate a
 * SSL Socket Factory based on the provided certificates.
 * The original code is by Sharon Asher (link below). I have modified
 * it to use a newer version of the BouncyCastle Library (v1.52)
 * 
 * Reference - https://gist.github.com/sharonbn/4104301"
 */

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;



import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;

public class SslUtil {

    public static SSLSocketFactory getSocketFactory(final String caCrtFile, final String crtFile, final String keyFile,
                                                    final String password) {
        try {
        		
            /**
             * Add BouncyCastle as a Security Provider
             */
            Security.addProvider(new BouncyCastleProvider());

            JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter().setProvider("BC");

            /**
             * Load Certificate Authority (CA) certificate
             */
            PEMParser reader = new PEMParser(new FileReader(caCrtFile));
            X509CertificateHolder caCertHolder = (X509CertificateHolder) reader.readObject();
            reader.close();

            X509Certificate caCert = certificateConverter.getCertificate(caCertHolder);

            /**
             * Load client certificate
             */
            reader = new PEMParser(new FileReader(crtFile));
            X509CertificateHolder certHolder = (X509CertificateHolder) reader.readObject();
            reader.close();

            X509Certificate cert = certificateConverter.getCertificate(certHolder);

            /**
             * Load client private key support PKCS#5 not support PKCS#8
             */
            reader = new PEMParser(new FileReader(keyFile));
            Object keyObject = reader.readObject();
            reader.close();
            KeyPair key;
            
            BouncyCastleProvider bcprovider = new BouncyCastleProvider();
	        JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider(bcprovider);
	        if (keyObject instanceof PEMEncryptedKeyPair) {
	        	// PKCS1 encrypted key
	        	 PEMDecryptorProvider provider = new JcePEMDecryptorProviderBuilder().setProvider(bcprovider).build(password.toCharArray());
	        	 key = keyConverter.getKeyPair(((PEMEncryptedKeyPair) keyObject).decryptKeyPair(provider));
	        } else if (keyObject instanceof PKCS8EncryptedPrivateKeyInfo){
	        	// PKCS8 encrypted key
	            InputDecryptorProvider decryptionProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(bcprovider).build(password.toCharArray());
	            PrivateKeyInfo keyInfo = ((PKCS8EncryptedPrivateKeyInfo) keyObject).decryptPrivateKeyInfo(decryptionProvider);
	            PrivateKey prikey;
            	PublicKey  pubkey; 
            	prikey = keyConverter.getPrivateKey(keyInfo);
            	RSAPrivateCrtKey privk = (RSAPrivateCrtKey)prikey;
                RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                pubkey = keyFactory.generatePublic(publicKeySpec);
                KeyPair p8key=new KeyPair(pubkey,prikey);
                key = p8key;
	        }else{
	        	 key = keyConverter.getKeyPair((PEMKeyPair) keyObject);
	        }   
            
            /**
             * CA certificate is used to authenticate server
             */
            KeyStore caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            caKeyStore.load(null, null);
            caKeyStore.setCertificateEntry("ca-certificate", caCert);

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(caKeyStore);

            /**
             * Client key and certificates are sent to server so it can authenticate the client
             */
            KeyStore clientKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            clientKeyStore.load(null, null);
            clientKeyStore.setCertificateEntry("certificate", cert);
            clientKeyStore.setKeyEntry("private-key", key.getPrivate(), password.toCharArray(),
                    new Certificate[]{cert});

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(clientKeyStore, password.toCharArray());

            /**
             * Create SSL socket factory
             */
            SSLContext context = SSLContext.getInstance("TLSv1.2");
            context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

            /**
             * Return the newly created socket factory object
             */
            return context.getSocketFactory();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}
