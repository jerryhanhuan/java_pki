package demo.tcp.test1;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class SSLClient {

	 private static final String CLIENT_KEY_STORE = "src/demo/tcp/test1/kclient.keystore";
	 private static final String CLIENT_TRUST_STORE = "src/demo/tcp/test1/tclient.keystore";
	 
	 private static final String DEFAULT_HOST     = "192.1.2.229";
	 private static final int DEFAULT_PORT     = 1818;
	 private static final String CLIENT_KEY_STORE_PASSWORD  = "123456";
	 private static final String CLIENT_TRUST_KEY_STORE_PASSWORD = "123456";
	 private SSLSocket   h;
	 private BufferedOutputStream byteos;
	 private BufferedInputStream bytein;
	 public boolean ok = false;
		
	 
	   public void init(String ip,int port)
	   {
		   try {
			SSLContext ctx = SSLContext.getInstance("SSL");
			
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			KeyStore ks = KeyStore.getInstance("JKS");
			KeyStore tks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(CLIENT_KEY_STORE), CLIENT_KEY_STORE_PASSWORD.toCharArray());
			tks.load(new FileInputStream(CLIENT_TRUST_STORE), CLIENT_TRUST_KEY_STORE_PASSWORD.toCharArray());
			kmf.init(ks, CLIENT_KEY_STORE_PASSWORD.toCharArray());
			tmf.init(tks);
			ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			//ctx.init(null, tmf.getTrustManagers(), null); // 单向验证
			h = (SSLSocket) ctx.getSocketFactory().createSocket(ip, port);
			
			h.setSoLinger(true, 0);
			h.setSoTimeout(10000);//change 100000 to 10000  10sec

			byteos = new BufferedOutputStream(h.getOutputStream());
			bytein = new BufferedInputStream(h.getInputStream());
			ok = true;
			
			
		   } catch (Exception  e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		   
	   }
	 
	 
		public boolean connectHSM(String ip, int port) throws Exception {
			try {
				SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory  
	            .getDefault();  
				h = (SSLSocket) factory.createSocket(ip, port); 
				
				//h.connect(new InetSocketAddress(ip, port), 15000);//15 sec
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
		//System.out.println(System.getProperty("user.dir"));//user.dir指定了当前的路径 
		//System.setProperty("javax.net.debug", "ssl,handshake"); 
		String ip = "192.1.2.235";
		int port = 2822;
		SSLClient cli = new SSLClient();
		cli.init(ip,port);
		//cli.connectHSM(ip, port);
		String cmd = "NC";
		byte[] res = cli.HsmSend(cmd.getBytes(), cmd.length());
		System.out.println(new String(res));
		cli.allClose();
	}

}
