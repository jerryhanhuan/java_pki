package demo.tcp.test1;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;



public class Client {

	
	private Socket h;
	private BufferedOutputStream byteos;
	private BufferedInputStream bytein;
	public boolean ok = false;
	
	public boolean connectHSM(String ip, int port) throws Exception {
		try {
			h = new Socket();
			h.connect(new InetSocketAddress(ip, port), 15000);//15 sec
			h.setSoLinger(true, 0);
			h.setSoTimeout(10000);//change 100000 to 10000  10sec

			byteos = new BufferedOutputStream(h.getOutputStream());
			bytein = new BufferedInputStream(h.getInputStream());
			ok = true;
		} catch (SocketException e) {
			ok = false;
			e.printStackTrace();
			System.out.println("in connectHSM::err "+e.toString());
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (!ok) {
				allClose();
				return false;
			}
		}
		return true;
	}
	
	
	private void HsmSendCmd(byte[]in,int len)throws Exception{
		try{
			int alllen = len+2;
			byte []cmd = new byte[alllen];
			cmd[0]=(byte) (len/256);
			cmd[1]=(byte) (len%256);
			System.arraycopy(in, 0, cmd, 2, len);
			byteos.write(cmd, 0, alllen);
			byteos.flush();
		}catch(Exception e){
			e.printStackTrace();
		}	
	}

	private byte[] HsmRecvCmd()throws Exception{
		byte[] outbyte = null;
		byte[] lenhead=new byte[2];
		int len = 0;
		try{
			bytein.read(lenhead,0,2);
			len = lenhead[0]*256+lenhead[1];
			outbyte = new byte[len];
			int offset = 0;
			int count = 0;
			while(offset<len)
			{
				count = bytein.read(outbyte,offset,len-offset);
				offset+=count;
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		return outbyte;
	}
	
   
	public byte[] HsmSend(byte[] msg,int len)throws Exception{
		
		HsmSendCmd(msg,len);
		return HsmRecvCmd();	
	}
	
	
	
	public void allClose() {
	    ok = false;
	try {
		if (bytein != null) {
			bytein.close();
			bytein = null;
		}
		if (byteos != null) {
			byteos.close();
			byteos = null;
		}
		if (h != null) {
			h.close();
			h = null;
		}
	} catch (Exception e) {
		;
	}
}
	/**
	 * @param args
	 */
	public static void main(String[] args)throws Exception {
		// TODO Auto-generated method stub
		
		
			String ip = "192.1.2.237";
			int port = 1818;
			Client cli = new Client();
			cli.connectHSM(ip, port);
			String cmd = "12345678NC";
			byte[] res = cli.HsmSend(cmd.getBytes(), cmd.length());
			System.out.println(new String(res));
			cli.allClose();
		
	}

}
