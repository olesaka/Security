import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.lang.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import javax.xml.bind.DatatypeConverter;


// Class performs the chat functionality of a client
// @authors: Andrew Olesak, Joey Seder, Keith Rodgers
public class client{
	public static void main(String[] args){
		try{

			// // create a socket channel and create a connection
			SocketChannel sc = SocketChannel.open();
			sc.connect(new InetSocketAddress("35.39.165.109",9876));

			cryptotest crypto = new cryptotest();
			// read in the public key
			crypto.setPublicKey("RSApub.der");
			// create a symmetric key and encrypt it
			crypto.setSecretKey(crypto.generateAESKey());
			byte encryptedsecret[] = crypto.RSAEncrypt(crypto.getSecretKey().getEncoded());
			// cocnvert the encrypted symmetric key and send it to the server
			ByteBuffer b = ByteBuffer.wrap(encryptedsecret);
			sc.write(b);

			// create the iv and set it		
			byte ivbytes[] = crypto.createIV();


			// read in the username for this client
			Console cons = System.console();
			String username = cons.readLine("Please enter a username: ");
			byte nameByte[] = crypto.encrypt(username.getBytes(), crypto.getSecretKey(), new IvParameterSpec(ivbytes));
			byte userNameIv[] = crypto.addIV(nameByte, ivbytes);
			b = ByteBuffer.wrap(userNameIv);
			// send the username to the server

			sc.write(b);
			String message;
			// create a thread to received messages from
			ClientThread ct = new ClientThread(sc, crypto);
			ct.start();
			while(true){
				// accepts input from the client
				message = cons.readLine();
				ivbytes = crypto.createIV();
				byte messagebytes[] = crypto.encrypt(message.getBytes(), crypto.getSecretKey(), new IvParameterSpec(ivbytes));
				byte messageIv[] = crypto.addIV(messagebytes,ivbytes);
				ByteBuffer buf = ByteBuffer.wrap(messageIv);
				sc.write(buf);
			}


		}catch (IOException e){
			System.out.print("Error");
		}
	}
}

// thread class to accept messages sent to this client
class ClientThread extends Thread{
	SocketChannel sc;
	cryptotest crypto;

	public ClientThread(SocketChannel s, cryptotest ct){
		sc = s;
		crypto = ct;
	}

	public void run(){
		try{
			// accepts messages from the server
			while(true){
				ByteBuffer buf = ByteBuffer.allocate(1024);
				if(sc.read(buf)!=-1){
					buf.flip();
					// decrypt the received message
					byte messageBytes[] = crypto.bufferToArray(buf);
					byte ivbytes[] = crypto.getOnlyIv(messageBytes);
					byte messageOnly[] = crypto.getOnlyMessage(messageBytes);
					byte realMessage[] = crypto.decrypt(messageOnly, crypto.getSecretKey(), new IvParameterSpec(ivbytes));
					// put unencrypted
					String message = new String(realMessage);
					if(message.substring(0,5).equals("Sorry")){
						sc.close();
						System.out.println(message);
						System.exit(0);
					}
					System.out.println(message);
				}
			}
		}catch(IOException e){
			System.out.println("IO Exception " + e);
		}
	}
}

class cryptotest{
    private PublicKey pubKey;
    private SecretKey s;
    private IvParameterSpec ivCode;


    public cryptotest(){
		pubKey=null;
		s=null;
		ivCode=null;
    }

    public void setSecretKey(SecretKey sk){
    	s = sk;
    	return;
    }

    public SecretKey getSecretKey(){
    	return s;
    }

    public byte[] createIV(){
		SecureRandom r = new SecureRandom();
		byte ivbytes[] = new byte[16];
		r.nextBytes(ivbytes);
		return ivbytes;
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
		    System.out.println("AES Decrypt Exception");
		    System.exit(1);
		    return null;
		}
    }

    public byte[] RSAEncrypt(byte[] plaintext){
		try{
		    Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
		    c.init(Cipher.ENCRYPT_MODE,pubKey);
		    byte[] ciphertext=c.doFinal(plaintext);
		    return ciphertext;
		}catch(Exception e){
		    System.out.println("RSA Encrypt Exception");
		    System.exit(1);
		    return null;
		}
    }

    public SecretKey generateAESKey(){
		try{
		    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		    keyGen.init(128);
		    SecretKey secKey = keyGen.generateKey();
		    return secKey;
		}catch(Exception e){
		    System.out.println("Key Generation Exception");
		    System.exit(1);
		    return null;
		}
    }

    public void setPublicKey(String filename){
		try{
		    File f = new File(filename);
		    FileInputStream fs = new FileInputStream(f);
		    byte[] keybytes = new byte[(int)f.length()];
		    fs.read(keybytes);
		    fs.close();
		    X509EncodedKeySpec keyspec = new X509EncodedKeySpec(keybytes);
		    KeyFactory rsafactory = KeyFactory.getInstance("RSA");
		    pubKey = rsafactory.generatePublic(keyspec);
		}catch(Exception e){
		    System.out.println("Public Key Exception");
		    System.exit(1);
		}
    }
}