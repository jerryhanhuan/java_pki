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
		 return DES_encrypt(key,data);
		 
	 }
	 
	 public static byte[] DecryptPasswd(byte[] key,byte[] data){
		 byte[] result = DES_decrypt(key,data);
		 return Trim_pkcs5(result,paddingsize);
		 
	 }
	 
	 
	 
	 
	 
	
	
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			byte[] key={0x32,0x40,0x64,0x58,0x3E,0x75,0x4A,0x2F};
			byte[] data={0x12,0x34,0x56,0x05,0x05,0x05,0x05,0x05};
			System.out.println("key: "+HexUtil.bcdhex_to_aschex(key));
			System.out.println("data: "+HexUtil.bcdhex_to_aschex(data));
			byte[] result = null;
			//加密
			result = DES_encrypt(key,data);
			System.out.println("result: "+HexUtil.bcdhex_to_aschex(result));
			
			//解密
			byte[] result2 = null;
			result2 = DES_decrypt(key,result);
			System.out.println("result: "+HexUtil.bcdhex_to_aschex(result2));
			
			
			String passwd = "123456";
			byte[] enc_passwd = EncryptPasswd(key,passwd.getBytes());
			System.out.println("enc_passwd: "+HexUtil.bcdhex_to_aschex(enc_passwd));
			
			byte[] passwd_1 = DecryptPasswd(key, enc_passwd);
			System.out.println(new String(passwd_1));
			
			String keyHex = "324064583E754A2F11111111111111111234560505050505";
			String dataHex= "121313131314313413412341234123412341234132435345345241324123412341234132412341341324132412341322";
			byte[] a = TDES_encrypt(HexUtil.aschex_to_bcdhex(keyHex), HexUtil.aschex_to_bcdhex(dataHex));
			System.out.println("a: "+HexUtil.bcdhex_to_aschex(a));
			System.out.println("b:"+HexUtil.bcdhex_to_aschex(TDES_decrypt(HexUtil.aschex_to_bcdhex(keyHex), a)));
			
			
			
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		

	}

}
