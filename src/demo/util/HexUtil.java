package demo.util;

public class HexUtil {

	
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


	public static String bcdhex_to_aschex(byte[] bcdhex) {
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
	public static byte[] aschex_to_bcdhex(String aschex) {
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
	
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
