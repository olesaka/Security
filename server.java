import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import javax.xml.bind.DatatypeConverter;


/*
	File performs basic functionality of a server
	@authors: Andrew Olesak, Joseph Seder, Keith Rodgers
*/

// class allows the server to connect with multiple client
public class server {

	ArrayList<SocketChannel> sockets;
	ArrayList<String> users;
	ArrayList<SecretKey> keys;

	public server(){
		sockets = new ArrayList<SocketChannel>();
		users = new ArrayList<String>();
		keys = new ArrayList<SecretKey>();
	}

	public static void main(String[] args) throws FileNotFoundException {
		try {
			// create a channel to send information
			ServerSocketChannel c = ServerSocketChannel.open();
			Console cons = System.console();

			c.bind(new InetSocketAddress(9876));

			server s = new server();
			cryptotest crypto = new cryptotest();
			crypto.setPrivateKey("RSApriv.der");
			// continually loop and search for connections
			while (true) {
				// accept a socket channel in a new thread
				SocketChannel sc = c.accept();
				s.addSocket(sc);
				ServerThread t = new ServerThread(sc, s, crypto);
				t.start();
			}

		} catch (Exception e) {
			System.out.println(e);
		}
	}

	// method adds a socket channel to the arraylist
	public void addSocket(SocketChannel sc){
		this.sockets.add(sc);
		return;
	}

	// method adds a username to the arraylist
	public void addUser(String u){
		this.users.add(u);
		return;
	}

	public SocketChannel getSocket(int index){
		return sockets.get(index);
	}

	// returns the sockets arraylist
	public ArrayList<SocketChannel> getSockets(){
		return this.sockets;
	}

	public int getSocketIndex(SocketChannel s){
		return this.sockets.indexOf(s);
	}

	// returns the list of usernames
	public ArrayList<String> getUsers(){
		return this.users;
	}

	// returns the user at the given index
	public String getUser(int i){
		return this.users.get(i);
	}

	// removes a user
	public void removeUser(int i){
		this.users.remove(i);
	}

	// removes a socket
	public void removeSocket(int i){
		this.sockets.remove(i);
	}

	public void addKey(SecretKey sk){
		this.keys.add(sk);
	}

	public SecretKey getKey(int index){
		return this.keys.get(index);
	}

	public void removeKey(int index){
		this.keys.remove(index);
	}

	// returns a string of just the users name
	public String getOnlyName(String str){
		int index = 0;
		for(int i=0; i<str.length(); i++){
			if(str.charAt(i)==' '){
				index = i;
				break;
			}
		}
		return str.substring(0,index);
	}

	// replaces the name at the beginning of the string
	// with the name of the sender
	public String replace(SocketChannel s, String m){
		int index = getSocketIndex(s);
		String name = getUser(index);
		int spot = 0;
		for(int i=0; i<m.length(); i++){
			if(m.charAt(i)==' '){
				spot = i;
				break;
			}
		}
		return m = name+":"+m.substring(spot);
	}


	// puts the contents of an arraylist of strings
	// and puts them into one string separated by 
	// new line characters
	public String makeList(ArrayList<String> names, int index){
		String u = "Connected Users:\n";
		for(int i=0; i<names.size(); i++){
			if(index!=i){
				if(i==names.size()-1 || (index==names.size()-1 && i==names.size()-2)){
					u+=names.get(i);
				}else{
					u+=names.get(i)+"\n";
				}
			}
		}
		return u;
	}

	// returns the index of the given user
	// returns negative one if it is not found
	public int findUser(String u){
		for(int i=0; i<this.users.size(); i++){
			if(this.users.get(i).equals(u)){
				return i;
			}
		}
		return -1;
	}
}

// class allows the server to connect to multiple clients using a thread
class ServerThread extends Thread {
	// create the socketchannel
	SocketChannel sc;
	String username;
	server s;
	SocketChannel sock;
	cryptotest crypto;

	// create a thread
	ServerThread(SocketChannel channel, server serv, cryptotest ct) {
		sc = channel;
		s = serv;
		username = "";
		crypto = ct;
	}

	public void run() {
		try {
			// get the symmetric key and add it to the arraylist
			ByteBuffer b = ByteBuffer.allocate(4096);
			sc.read(b);
			b.flip();
			byte symKey[] = new byte[b.remaining()];
			b.get(symKey);
			symKey = crypto.RSADecrypt(symKey);
			SecretKey secret = new SecretKeySpec(symKey,"AES");
			s.addKey(secret);

			// accept the username for the given client connection
			ByteBuffer userbytes = ByteBuffer.allocate(1024);
			sc.read(userbytes);		
			userbytes.flip();
			byte secretMessage[] = crypto.bufferToArray(userbytes);
			byte ivbytes[] = crypto.getOnlyIv(secretMessage);
			byte messageOnly[] = crypto.getOnlyMessage(secretMessage);
			byte usernameBytes[] = crypto.decrypt(messageOnly, secret, new IvParameterSpec(ivbytes));
			username = new String(usernameBytes);
			username = username.trim();
			s.addUser(username);
			System.out.println(username + " is connected");
			while(true){
			   	ByteBuffer buffer = ByteBuffer.allocate(1024);
			   	// check to make sure that this socket still has as connection
			    if(sc.read(buffer)!=-1){
			    	int spot = s.getSocketIndex(sc);
			    	buffer.flip();
			    	byte encrypted[] = crypto.bufferToArray(buffer);
			    	byte ivCode[] = crypto.getOnlyIv(encrypted);
			    	byte encryptedMessage[] = crypto.getOnlyMessage(encrypted);
			    	byte decryptedMessage[] = crypto.decrypt(encryptedMessage, s.getKey(spot), new IvParameterSpec(ivCode));

				    String message  = new String(decryptedMessage);
				    message = message.trim();

				    // create an iv array to work with
				    byte ivArray[] = crypto.createIV();
				    // check for broadcast message
				    if(message.length()>2 && message.substring(0,3).equals("all")){
				    	// send message to all users
				    	// first get all of the user's sockets
				    	message = s.replace(sc, message);
				    	ArrayList<SocketChannel> sockets = s.getSockets();
				    	for(SocketChannel schannel : sockets){
				    		if(schannel!=sc){
				    			int loc = s.getSocketIndex(schannel);
				    			ivArray = crypto.createIV();
					    		byte encryptedMess[] = crypto.encrypt(message.getBytes(), s.getKey(loc), new IvParameterSpec(ivArray));
					    		byte broadcastIV[] = crypto.addIV(encryptedMess, ivArray);

					    		buffer = ByteBuffer.wrap(broadcastIV);
					    		schannel.write(buffer);
				    		}
				    	}
				    // check to see if someone is getting kicked off
				    }else if(message.length()>3 && message.substring(0,2).equals("rm")){
				    	int index = s.findUser(message.substring(3));
				    	if(index==-1){
				    		index = s.getSocketIndex(sc);
				    		message = "Please enter a valid user";
				    		byte encryptedMess[] = crypto.encrypt(message.getBytes(), s.getKey(index), new IvParameterSpec(ivArray));
				    		byte validIV[] = crypto.addIV(encryptedMess, ivArray);
				    		ByteBuffer b2 = ByteBuffer.wrap(validIV);
				    		sc.write(b2);
				    	}else{
					    	SocketChannel sock = s.getSocket(index);
					    	String remove = "Sorry, but you have been disconnected";
				    		byte encryptedMess[] = crypto.encrypt(remove.getBytes(), s.getKey(index), new IvParameterSpec(ivArray));
				    		byte exitIV[] = crypto.addIV(encryptedMess, ivArray);
					    	ByteBuffer b2 = ByteBuffer.wrap(exitIV);
					    	sock.write(b2);
					    	System.out.println(s.getUser(index)+" has be disconnected");
					    	s.removeUser(index);
					    	s.removeSocket(index);
					    	s.removeKey(index);
				    	}
				    // check to see if the client wants a list of 
				    // all other connected users
				    }else if(message.length()>4 && message.substring(0,5).equals("users")){
				    	int index = s.getSocketIndex(sc);
				    	ArrayList<String> list = s.getUsers();
				    	String namesList = s.makeList(list, index);
				    	byte encryptedNames[] = crypto.encrypt(namesList.getBytes(), secret, new IvParameterSpec(ivArray));
				    	byte namesIv[] = crypto.addIV(encryptedNames, ivArray);
				    	ByteBuffer userbuf = ByteBuffer.wrap(namesIv);
				    	sc.write(userbuf);
				    }else{
					    int index = s.findUser(s.getOnlyName(message));			    
					    if(index!=-1){
					    	message = s.replace(sc, message);

				    		byte encryptedMess[] = crypto.encrypt(message.getBytes(), s.getKey(index), new IvParameterSpec(ivArray));
				    		byte namesIv[] = crypto.addIV(encryptedMess, ivArray);
				    		ByteBuffer userbuf = ByteBuffer.wrap(namesIv);

					    	buffer =ByteBuffer.wrap(namesIv);
					    	sock = s.getSocket(index);
					    	sock.write(buffer);
					    }
					}
				}
			}
		// catch any exceptions in the program
		} catch (IOException e) {
			System.out.println("IO Exception: " + e);
		}
	}
}





class cryptotest{
    private PrivateKey privKey;

    public cryptotest(){
		privKey=null;
    }

    // gets only the iv of the given byte
    // array and returns it
    public byte[] getOnlyIv(byte[] m){
    	byte ivbytes[] = new byte[16];
    	System.arraycopy(m, m.length-16, ivbytes, 0, 16);
    	return ivbytes;
    }

    // gets only the cipher text of the given
    // byte array and returns it
    public byte[] getOnlyMessage(byte[] m){
    	byte message[] = new byte[m.length-16];
    	System.arraycopy(m, 0, message, 0, message.length);
    	return message;
    }

    // converts the given bytebuffer to a
    // byte array and returns it
    public byte[] bufferToArray(ByteBuffer b){
    	byte b1[] = new byte[b.remaining()];
    	b.get(b1);
    	return b1;
    }

    public byte[] createIV(){
		SecureRandom r = new SecureRandom();
		byte ivbytes[] = new byte[16];
		r.nextBytes(ivbytes);
		return ivbytes;
    }

    // adds the IV to the end of the encrypted message
    public byte[] addIV(byte[] encrypted, byte[] iv){
    	int length = encrypted.length;
    	byte encIV[] = new byte[length+16];
    	System.arraycopy(encrypted, 0, encIV, 0, length);
    	System.arraycopy(iv, 0, encIV, length, 16);
    	return encIV;
    }

    public byte[] encrypt(byte[] plaintext, SecretKey secKey, IvParameterSpec iv){
		try{
		    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		    c.init(Cipher.ENCRYPT_MODE,secKey,iv);
		    byte[] ciphertext = c.doFinal(plaintext);
		    return ciphertext;
		}catch(Exception e){
		    System.out.println("AES Encrypt Exception");
		    System.exit(1);
		    return null;
		}
    }

    public byte[] decrypt(byte[] ciphertext, SecretKey secKey, IvParameterSpec iv){
		try{
		    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		    c.init(Cipher.DECRYPT_MODE,secKey,iv);
		    byte[] plaintext = c.doFinal(ciphertext);
		    return plaintext;
		}catch(Exception e){
			System.out.println(e);
		    System.out.println("AES Decrypt Exception");
		    System.exit(1);
		    return null;
		}
    }

    public byte[] RSADecrypt(byte[] ciphertext){
		try{
		    Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
		    c.init(Cipher.DECRYPT_MODE,privKey);
		    byte[] plaintext=c.doFinal(ciphertext);
		    return plaintext;
		}catch(Exception e){
			System.out.println(e);
		    System.out.println("RSA Decrypt Exception");
		    System.exit(1);
		    return null;
		}
    }

    public void setPrivateKey(String filename){
		try{
		    File f = new File(filename);
		    FileInputStream fs = new FileInputStream(f);
		    byte[] keybytes = new byte[(int)f.length()];
		    fs.read(keybytes);
		    fs.close();
		    PKCS8EncodedKeySpec keyspec = new PKCS8EncodedKeySpec(keybytes);
		    KeyFactory rsafactory = KeyFactory.getInstance("RSA");
		    privKey = rsafactory.generatePrivate(keyspec);
		}catch(Exception e){
		    System.out.println("Private Key Exception");
		    e.printStackTrace(System.out);
		    System.exit(1);
		}
    }
}
