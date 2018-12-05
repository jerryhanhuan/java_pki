package demo.ecc;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.LinkedList;



import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;




public class secp256K1 {


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
	
	
	private static final String RANDOM_NUMBER_ALGORITHM = "SHA1PRNG";
	  private static final String RANDOM_NUMBER_ALGORITHM_PROVIDER = "SUN";
	  private static final String SECP256K1 = "secp256k1";

	  public static final BigInteger MAXPRIVATEKEY =
	      new BigInteger("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 16);
	
	  /**
	   * Generate a random private key that can be used with Secp256k1.
	   */
	  public static  byte[] generatePrivateKey() {
	    SecureRandom secureRandom;
	    try {
	      secureRandom =
	          SecureRandom.getInstance(RANDOM_NUMBER_ALGORITHM, RANDOM_NUMBER_ALGORITHM_PROVIDER);
	    } catch (Exception e) {
	      secureRandom = new SecureRandom();
	    }

	    // Generate the key, skipping as many as desired.
	    byte[] privateKeyAttempt = new byte[32];
	    secureRandom.nextBytes(privateKeyAttempt);
	    BigInteger privateKeyCheck = new BigInteger(1, privateKeyAttempt);
	    while (privateKeyCheck.compareTo(BigInteger.ZERO) == 0
	        || privateKeyCheck.compareTo(MAXPRIVATEKEY) == 1) {
	      secureRandom.nextBytes(privateKeyAttempt);
	      privateKeyCheck = new BigInteger(1, privateKeyAttempt);
	    }

	    return privateKeyAttempt;
	  }

	  /**
	   * Converts a private key into its corresponding public key.
	   */
	  public static  byte[] getPublicKey(byte[] privateKey) {
	    try {
	      ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(SECP256K1);
	      ECPoint pointQ = spec.getG().multiply(new BigInteger(1, privateKey));

	      return pointQ.getEncoded(false);
	    } catch (Exception e) {
	      return new byte[0];
	    }
	  }
	  
	  
	  static void print(BigInteger[] P)                             
	  {
	  	String a = P[0].toString(16);
	  	String b = P[1].toString(16);
	  	System.out.printf(" |%S|",a); 
	  	System.out.printf(" |%S| \n",b);
	  }
	  
	  
	  /**
	   * Sign data using the ECDSA algorithm.
	   */
	  public static byte[][] signTransaction(byte[] data, byte[] privateKey) {
	    try {
	      Security.addProvider(new BouncyCastleProvider());
	      ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(SECP256K1);

	      ECDSASigner ecdsaSigner = new ECDSASigner();
	      ECDomainParameters domain = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN());
	      ECPrivateKeyParameters privateKeyParms =
	          new ECPrivateKeyParameters(new BigInteger(1, privateKey), domain);
	      ParametersWithRandom params = new ParametersWithRandom(privateKeyParms);

	      ecdsaSigner.init(true, params);

	      BigInteger[] sig = ecdsaSigner.generateSignature(data);
	      
	      
	      print(sig);
	      
	      LinkedList<byte[]> sigData = new LinkedList<byte[]>();
	      byte[] publicKey = getPublicKey(privateKey);
	      byte recoveryId = getRecoveryId(sig[0].toByteArray(), sig[1].toByteArray(), data, publicKey);
	      for (BigInteger sigChunk : sig) {
	    	System.out.println("sigChunk::"+sigChunk.toString(16));
	        sigData.add(sigChunk.toByteArray());
	      }
	      System.out.println("recoveryId::"+recoveryId);
	      sigData.add(new byte[]{recoveryId});
	      return sigData.toArray(new byte[][]{});

	    } catch (Exception e) {
	      return new byte[0][0];
	    }
	  }
	  
	  /**
	   * Determine the recovery ID for the given signature and public key.
	   *
	   * <p>Any signed message can resolve to one of two public keys due to the nature ECDSA. The
	   * recovery ID provides information about which one it is, allowing confirmation that the message
	   * was signed by a specific key.</p>
	   */
	  public static byte getRecoveryId(byte[] sigR, byte[] sigS, byte[] message, byte[] publicKey) {
	    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(SECP256K1);
	    BigInteger pointN = spec.getN();
	    for (int recoveryId = 0; recoveryId < 2; recoveryId++) {
	      try {
	        BigInteger pointX = new BigInteger(1, sigR);

	        X9IntegerConverter x9 = new X9IntegerConverter();
	        byte[] compEnc = x9.integerToBytes(pointX, 1 + x9.getByteLength(spec.getCurve()));
	        compEnc[0] = (byte) ((recoveryId & 1) == 1 ? 0x03 : 0x02);
	        ECPoint pointR = spec.getCurve().decodePoint(compEnc);
	        if (!pointR.multiply(pointN).isInfinity()) {
	          continue;
	        }

	        BigInteger pointE = new BigInteger(1, message);
	        BigInteger pointEInv = BigInteger.ZERO.subtract(pointE).mod(pointN);
	        BigInteger pointRInv = new BigInteger(1, sigR).modInverse(pointN);
	        BigInteger srInv = pointRInv.multiply(new BigInteger(1, sigS)).mod(pointN);
	        BigInteger pointEInvRInv = pointRInv.multiply(pointEInv).mod(pointN);
	        ECPoint pointQ = ECAlgorithms.sumOfTwoMultiplies(spec.getG(), pointEInvRInv, pointR, srInv);
	        byte[] pointQBytes = pointQ.getEncoded(false);
	        boolean matchedKeys = true;
	        for (int j = 0; j < publicKey.length; j++) {
	          if (pointQBytes[j] != publicKey[j]) {
	            matchedKeys = false;
	            break;
	          }
	        }
	        if (!matchedKeys) {
	          continue;
	        }
	        return (byte) (0xFF & recoveryId);
	      } catch (Exception e) {
	       
	      }
	    }

	    return (byte) 0xFF;
	  }
	  
	  
	  public static byte[] TrimLeftZero(byte[] data)
	  {
		  byte[] result =null;
		  int index = 0;
		  if(data[0] == 0x00)
		  {
			index = 1;  
			result = new byte[data.length-1];
		  }else
			  result = new byte[data.length];
		  
		 System.arraycopy(data, index, result, 0, data.length-index);
		 return result;
	  }
	  
	  
	  public static byte[] Sign(byte[] data, byte[] privateKey){
		  
		  try {
		      Security.addProvider(new BouncyCastleProvider());
		      ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(SECP256K1);

		      ECDSASigner ecdsaSigner = new ECDSASigner();
		      ECDomainParameters domain = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN());
		      ECPrivateKeyParameters privateKeyParms =
		          new ECPrivateKeyParameters(new BigInteger(1, privateKey), domain);
		      ParametersWithRandom params = new ParametersWithRandom(privateKeyParms);

		      ecdsaSigner.init(true, params);

		      BigInteger[] sig = ecdsaSigner.generateSignature(data);
		   	      
		      //System.out.println("oR::"+bcdhex_to_aschex(sig[0].toByteArray()));
		      //System.out.println("oS::"+bcdhex_to_aschex(sig[1].toByteArray()));
		      
		      byte []r = TrimLeftZero(sig[0].toByteArray());
		      byte []s = TrimLeftZero(sig[1].toByteArray());
		      byte[] result = new byte[r.length+s.length];
		      System.arraycopy(r, 0, result, 0, r.length);
		      System.arraycopy(s, 0, result, r.length, s.length);
		      
		      //System.out.println("R::"+bcdhex_to_aschex(r));
		      //System.out.println("S::"+bcdhex_to_aschex(s));
		     // System.out.println("R+S::"+bcdhex_to_aschex(result));
		      return result;
		      
		    } catch (Exception e) {
		      return null;
		    }
	  }
	  
	  
	  public static boolean verifySignature(byte[] sigR, byte sigS[], byte[] publicKey, byte[] message) {
		    try {
		      Security.addProvider(new BouncyCastleProvider());
		      ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(SECP256K1);
		      ECDomainParameters domain = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN());
		      ECPublicKeyParameters publicKeyParams =
		          new ECPublicKeyParameters(spec.getCurve().decodePoint(publicKey), domain);

		      ECDSASigner signer = new ECDSASigner();
		      signer.init(false, publicKeyParams);
		      return signer.verifySignature(message, new BigInteger(1, sigR), new BigInteger(1, sigS));
		    } catch (Exception e) {
		      return false;
		    }
		  }
	  
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
			/*
			byte[] prikey,pubkey;
			String prihex = "5C590BD5B5EE35F50C59FA4EA450CB0B5A35B7EEDCA8C991F13580D24162C5DB";
			prikey = aschex_to_bcdhex(prihex);
			
			//prikey = generatePrivateKey();
			pubkey=getPublicKey(prikey);
			
			System.out.println("prikey::"+bcdhex_to_aschex(prikey));
			System.out.println("pubkey::"+bcdhex_to_aschex(pubkey));
			*/
			byte[] prikey,pubkey;
			String prihex = "5C590BD5B5EE35F50C59FA4EA450CB0B5A35B7EEDCA8C991F13580D24162C5DB";
			prikey = aschex_to_bcdhex(prihex);
			//04+X+Y
			String pkH = "04315EABF335E212487EC0976BFAC24B6844FF4741E73DB75DE98DEA0551BF01A9E2BED81A4F06A78740E96805615BBFC72E337FF547EF2C8495741C9441046768";
			String dataH= "12113123123123241248623716357163";
			String signH= "A91595BEDF41FA8F4FBB45BDA58DFE35FE766E0479F294649137387A7AA19E668A2E9598F9057C1141E0D71CB6244194569A65E469865368A8C5829B18CACD7A";
			//String signH = "167C5B35FC5F6EC0EA157C97679763A63CEBDD6848213DA8A83B823EC4AD5A7497B6A7F7F5968FA59074D892AB47274AE2ECFF46094D117ABAEA15E7352DAC38";
			byte[] msg;
			byte[] r=new byte[32];
			byte[] s=new byte[32];
			byte[] sign;
			pubkey = aschex_to_bcdhex(pkH);
			msg = aschex_to_bcdhex(dataH);
			sign = aschex_to_bcdhex(signH);
			System.arraycopy(sign,0,r,0,32);
			System.arraycopy(sign,32,s,0,32);
			
			//04+X+Y
			System.out.println("pk::"+bcdhex_to_aschex(pubkey));
			System.out.println("data::"+bcdhex_to_aschex(msg));
			System.out.println("r::"+bcdhex_to_aschex(r));
			System.out.println("s::"+bcdhex_to_aschex(s));
			
			
			
			boolean result = verifySignature(r,s,pubkey,msg);
			System.out.println("result "+result);
			
			
			byte[]signature;
			signature = Sign(msg,prikey);
			System.out.println("signature::"+bcdhex_to_aschex(signature));
			
			
	}

}
