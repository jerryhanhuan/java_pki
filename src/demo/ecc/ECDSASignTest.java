package demo.ecc;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.ECNamedCurveTable;

import com.sun.org.apache.xml.internal.serializer.utils.Utils;

public class ECDSASignTest {
	

	static byte hexLowToAsc(byte xxc) {
		xxc &= 0x0f;
		if (xxc < 0x0a)
			xxc += '0';
		else
			xxc += 0x37;
		return (byte) xxc;
	}

	static byte hexHighToAsc(int xxc) {
		xxc &= 0xf0;
		xxc = xxc >> 4;
		if (xxc < 0x0a)
			xxc += '0';
		else
			xxc += 0x37;
		return (byte) xxc;
	}


	static String bcdhex_to_aschex(byte[] bcdhex) {
		byte[] aschex = { 0, 0 };
		String res = "";
		String tmp = "";
		for (int i = 0; i < bcdhex.length; i++) {
			aschex[1] = hexLowToAsc(bcdhex[i]);
			aschex[0] = hexHighToAsc(bcdhex[i]);
			tmp = new String(aschex);
			res += tmp;
		}
		return res;
	}
	static byte[] aschex_to_bcdhex(String aschex) {
		byte[] aschexByte = aschex.getBytes();
		int j = 0;
		if (aschexByte.length % 2 == 0) {
			j = aschexByte.length / 2;
			byte[] resTmp = new byte[j];
			for (int i = 0; i < j; i++) {
				resTmp[i] = ascToHex(aschexByte[2 * i], aschexByte[2 * i + 1]);
			}
			return resTmp;

		} else {
			j = aschexByte.length / 2 + 1;
			byte[] resTmp = new byte[j];
			for (int i = 0; i < j - 1; i++) {
				resTmp[i] = ascToHex((byte) aschexByte[2 * i],
						(byte) aschexByte[2 * i + 1]);
			}
			resTmp[j - 1] = ascToHex((byte) aschexByte[2 * (j - 1)], (byte) 0);
			return resTmp;
		}
	}

	static byte ascToHex(byte ch1, byte ch2) {
		byte ch;
		if (ch1 >= 'A')
			ch = (byte) ((ch1 - 0x37) << 4);
		else
			ch = (byte) ((ch1 - '0') << 4);
		if (ch2 >= 'A')
			ch |= (byte) (ch2 - 0x37);
		else
			ch |= (byte) (ch2 - '0');
		return ch;
	}
	
	
	private static String srcHex = "3082019130820117A0030201020206015252653F58300A06082A8648CE3D0403033031310B300906035504061302434E310F300D0603550407130661726F756E643111300F06035504031308736F6D6520677579301E170D3136303131383031343135335A170D3436303131313031343135335A3031310B300906035504061302434E310F300D0603550407130661726F756E643111300F06035504031308736F6D65206775793076301006072A8648CE3D020106052B81040022036200048786E3223C2E66BBB9F80F96A65D5EBBBEC3BB221F7C8CB02360CBAA9DDE3040772D1408AD8E4FD9423DAA6D84A9C26A8832022A1840CDAC2B76EB8E62BFAF94F68F5DC080367AF2BA7068D0D9D2506CC370CEB1850B07051455EBD3F61E4F0D300A06082A8648CE3D04030303680030650231008FD968280EC580A2FAD909B7CD50F1A329F2E33FB97B21F2B1EA075FAC0AF83491CE89CAD682DA3DE4EA2C89E638775802303F57EA779906B86DF123A037DF26CF8BC3E9222A9BEFF1AA094D8976D5C85235EC3FB30DD09D8DD9C1604CB5B178977D";
	private static String dHex = "308193020100301306072a8648ce3d020106082a8648ce3d0301070479307702010104202c9a47396e2dd9c5e7d6c51a5f938a2735908eea98888056e8e71389e885f2f0a00a06082a8648ce3d030107a1440342000429cf311a7bbe35c865e8f4a60237fb8f64a458d629790ad106e9df71606d75862ccb1962cefb689f630bc3590af1ac7cd6c1337d74638aff3bfca60d6d8ce7a5";
	private static String pkHex = "3059301306072a8648ce3d020106082a8648ce3d0301070342000429cf311a7bbe35c865e8f4a60237fb8f64a458d629790ad106e9df71606d75862ccb1962cefb689f630bc3590af1ac7cd6c1337d74638aff3bfca60d6d8ce7a5";
	
	private static String k256_pkHex = "3056301006072A8648CE3D020106052B8104000A0342000414BF901A6640033EA07B39C6B3ACB675FC0AF6A6AB526F378216085A93E5C7A28E3A7078E42CF7C6A2B165A884984A65A4259DA0B51C1BDE4548A46386FE8D77";
	private static String k256_srcHex = "68656C6C6F";  //hello
	private static String k256_signature = "3045022100A314A579FB9F30A804C172EEC4881ED603E661EED692797149DFDBCE24D671D202203CCFAB0603AD97C34864CAA22D42A24D0CB5750FCB159476B8AE30A11EDC0ED6";
	public static void main(String[] args) {
		ECDSASignTest.ECDSASignTest();
	}

	public static void ECDSASignTest() {
		try {
			
		
			System.out.println("私钥: " + dHex);
			byte [] d = aschex_to_bcdhex(dHex);
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(d);
			 
			KeyFactory keyFactory = KeyFactory.getInstance("EC");
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			//Signature signature = Signature.getInstance("SHA1withECDSA");
			Signature signature = Signature.getInstance("NONEwithECDSA");
			signature.initSign(privateKey);
			signature.update(aschex_to_bcdhex(ECDSASignTest.srcHex));
			byte[] res = signature.sign();
			System.out.println("签名：" + bcdhex_to_aschex(res));

			// 3.验证签名[公钥验签]
			//System.out.println("公钥: " + Utils.bytesToHexString(ecPublicKey.getEncoded()));
			//X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(ecPublicKey.getEncoded());
			
			System.out.println("公钥: " + pkHex);
			byte [] pk = aschex_to_bcdhex(pkHex);
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pk);
			
			keyFactory = KeyFactory.getInstance("EC");
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
			signature = Signature.getInstance("NONEwithECDSA");
			signature.initVerify(publicKey);
			signature.update(aschex_to_bcdhex(ECDSASignTest.srcHex));
			boolean bool = signature.verify(res);
			System.out.println("验证：" + bool);
			
			
			System.out.println("公钥: " + k256_pkHex);
			
			pk = aschex_to_bcdhex(k256_pkHex);
			res =aschex_to_bcdhex(k256_signature);
			x509EncodedKeySpec = new X509EncodedKeySpec(pk);
			
			keyFactory = KeyFactory.getInstance("EC");
			publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
			signature = Signature.getInstance("SHA256withECDSA");
			signature.initVerify(publicKey);
			signature.update("hello".getBytes());
			bool = signature.verify(res);
			System.out.println("验证：" + bool);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
