package demo.des;

import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.sun.org.apache.bcel.internal.generic.NEW;
import com.sun.xml.internal.bind.v2.runtime.reflect.opt.Const;

import demo.util.*;

public class DesUtil {

	 public final static String DES = "DES";
	 public final static String TDES = "DESede";
	 static  int paddingsize = 8;
	
	/**
     * 加密
     * @param data byte[]
     * @param key byte[]
     * @return byte[]
     */
	 public static byte[] DES_encrypt(byte[] key, byte[] data){
		 try{
			 SecretKey secretKey = new SecretKeySpec(key, DES);
	         Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
	         // 用密钥初始化Cipher对象
	         cipher.init(Cipher.ENCRYPT_MODE, secretKey);
	         return cipher.doFinal(data);
	         
		 }catch(Exception e){
			 e.printStackTrace();
		 }
		 return null;
	 }
	 
	 public static byte[] DES_decrypt(byte[] key, byte[] data){
		 	
		 	try {
		 		SecretKey secretkey = new SecretKeySpec(key, DES);
			 	Cipher  cipher= Cipher.getInstance("DES/ECB/NoPadding");
				cipher.init(Cipher.DECRYPT_MODE,secretkey);
				return cipher.doFinal(data);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		 	return null;
	 }
	 
	 
	 public static byte[] TDES_encrypt(byte[] key, byte[] data){
		 try{
			 SecretKey secretKey = new SecretKeySpec(key, TDES);
	         Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
	         // 用密钥初始化Cipher对象
	         cipher.init(Cipher.ENCRYPT_MODE, secretKey);
	         return cipher.doFinal(data);
	         
		 }catch(Exception e){
			 e.printStackTrace();
		 }
		 return null;
	 }
	 
	 public static byte[] TDES_decrypt(byte[] key, byte[] data){
		 	
		 	try {
		 		SecretKey secretkey = new SecretKeySpec(key, TDES);
			 	Cipher  cipher= Cipher.getInstance("DESede/ECB/NoPadding");
				cipher.init(Cipher.DECRYPT_MODE,secretkey);
				return cipher.doFinal(data);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		 	return null;
	 }
	 
	 
	 
	 
	 public static byte[] pkcs5_padding(byte[] data,int size){
		 int datalen = data.length;
		 int padlen = size - datalen%size;
		 byte padcharacter = (byte)padlen;
		 byte[] result = new byte[datalen+padlen];
		 System.arraycopy(data, 0, result, 0, datalen);
		 for (int i = datalen; i < datalen+padlen; i++) {
			 result[i] = padcharacter;
		}
		return result; 
	 }
	 
	 public static byte[] Trim_pkcs5(byte[] data,int size){
		 byte padcharacter = data[data.length-1];
		 int padlen = padcharacter;
		 int datalen = data.length-padlen;
		 byte []result = new byte[datalen];
		 System.arraycopy(data, 0, result, 0, datalen);
		 return result;
	 }
	 
	 
	 public static byte[] EncryptPasswd(byte[] key, byte[] password){
		 byte []data = pkcs5_padding(password,paddingsize);
		 return TDES_encrypt(key,data);
		 
	 }
	 
	 public static byte[] DecryptPasswd(byte[] key,byte[] data){
		 byte[] result = TDES_decrypt(key,data);
		 return Trim_pkcs5(result,paddingsize);
		 
	 }
	 
	 
	 
	 
	 
	
	
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			byte[] key={0x32,0x40,0x64,0x58,0x3E,0x75,0x4A,0x2F,0x2A,0x6B,0x31,0x68,0x16,0x7F,0x3E,0x34,0x31,0x42,0x70,0x7F,0x64,0x5C,0x2C,0x25};
			
			String passwd = "123456";
			byte[] enc_passwd = EncryptPasswd(key,passwd.getBytes());
			System.out.println("enc_passwd: "+HexUtil.bcdhex_to_aschex(enc_passwd));
			
			byte[] passwd_1 = DecryptPasswd(key, enc_passwd);
			System.out.println(new String(passwd_1));
			
			
			
			
			
			
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		

	}

}
