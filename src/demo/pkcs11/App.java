package demo.pkcs11;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

//import sun.security.pkcs11.SunPKCS11;

import java.security.*;

/**
* Test App!
*
*/
public class App {
/*
    public static void main(String[] args) throws Exception {
    	char[] pinCode = "12345678".toCharArray();
        String config = "C:\\nfast\\etc\\pkcs11_config";

        Provider provider = new SunPKCS11(config);
        Security.addProvider(provider);

        KeyStore keystore = KeyStore.getInstance("PKCS11");
        keystore.load(null, pinCode);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES", provider);
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection("12345678".toCharArray());
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(aesKey);
        keystore.setEntry("myAesKey", entry, protectionParam);
        System.out.println("setEntry ok");

    }
*/
}













