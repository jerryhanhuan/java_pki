package demo.tcp.test1;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class Server extends Thread{

	private Socket socket;
	
	public Server(Socket socket){
		this.socket = socket;
	}
	public void run(){
		try{
			 BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));  
			 PrintWriter writer = new PrintWriter(socket.getOutputStream());  
	         String data = reader.readLine();  
	         writer.println(data);  
	         writer.close();  
	         socket.close();  
			
		}catch(IOException  e){
			System.out.println("err:"+e.toString());
		}
	}
	
	
	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception{
		// TODO Auto-generated method stub
		String ip = "0.0.0.0";
		int port = 1234;
		while(true){
				new Server((new ServerSocket(1234)).accept()).start(); 
		}
	}

}
