package cli;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.sql.SQLException;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;
import org.xml.sax.SAXException;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class RSATools {
	protected static final String ALGORITHM = "RSA";
	private String PRIVATE_KEY_FILE; // Private key file.
	private String PUBLIC_KEY_FILE; // Public key file.
	private static RSAPrivateKey privateKey; // Private Key Class
	private static RSAPublicKey publicKey; // Public Key Class
	private static RSAPublicKeySpec pubKeySpec;
	private static RSAPrivateCrtKeySpec privKeySpec;	
	private static RSATools instance;
	
	private static String public_Modulus;
	private static String public_Exponent;
	
	private static String private_Modulus;
	private static String private_Exponent;
	private static String private_P; 
	private static String private_Q;
	private static String private_DP;
	private static String private_DQ;
	private static String private_InverseQ;
	private static String private_D;
		
	private static int _EncryptionKeySize = 1024;
	private static int _EncryptionBufferSize = 117;
	private static int _DecryptionBufferSize = 128;
	
	public RSATools(){		
		init();
	}

	public static void init(){
		Security.addProvider(new BouncyCastleProvider());
		privateKey = null;
		publicKey  = null;
		pubKeySpec = null;
		privKeySpec = null;
	}

	public static synchronized RSATools getInstance() {
        if(instance == null)
            instance = new RSATools();
        return instance;
    }
    
    public boolean SetKeyPath(String strPriveKey, String strPublicKey)  {
    	PRIVATE_KEY_FILE = strPriveKey; //Location of private key file
		PUBLIC_KEY_FILE = strPublicKey; //Location of Public key file	
		return verifyKey();
    }
    
	private void readPrivateKeyFile() throws IOException{
		BigInteger privateModulus = null;	
		BigInteger privateExponent = null;		
		BigInteger privateP= null;
		BigInteger privateQ= null;
		BigInteger privateDP= null;
		BigInteger privateDQ= null;
		BigInteger privateInverseQ= null;
		BigInteger privateD= null;
		
		readKeyBytesFromFile(PRIVATE_KEY_FILE, "private");
		
		try {
			privateModulus = new BigInteger(1, decodeBASE64(private_Modulus));
			privateExponent = new BigInteger(1, decodeBASE64(private_Exponent));
			privateP = new BigInteger(1, decodeBASE64(private_P));
			privateQ = new BigInteger(1, decodeBASE64(private_Q));
			privateDP = new BigInteger(1, decodeBASE64(private_DP));
			privateDQ = new BigInteger(1, decodeBASE64(private_DQ));
			privateInverseQ = new BigInteger(1, decodeBASE64(private_InverseQ));
			privateD = new BigInteger(1, decodeBASE64(private_D));
		} catch (Exception e) {
			e.printStackTrace();
		}
		privKeySpec = new RSAPrivateCrtKeySpec(privateModulus, privateExponent,
				privateExponent,privateP, privateQ, 
				privateDP, privateDQ, privateInverseQ);

		try {		
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}		
	}

	//Reads Public key @return byte[] public key
	private void readPublicKeyFile() throws IOException {
		BigInteger publicModulus = null;	
		BigInteger publicExponent = null;		
		
		readKeyBytesFromFile(PUBLIC_KEY_FILE, "public");
		try {
			publicModulus = new BigInteger(1, decodeBASE64(public_Modulus));
			publicExponent = new BigInteger(1, decodeBASE64(public_Exponent));
		} catch (Exception e1) {
			e1.printStackTrace(); 
		}
				
		pubKeySpec = new RSAPublicKeySpec(publicModulus, publicExponent);

		try {			//RSA/ECB/PKCS1Padding
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");			
			publicKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		//return publicKey;
	}

	//Returns the contents of the file in a byte array.
	//@param fileName File Name
	//@return byte[] Teh data read from a given file as a byte array.
	private boolean readKeyBytesFromFile(String fileName, String skey) throws IOException{
		try {
            File file = new File(fileName);

            DocumentBuilderFactory dbfactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = dbfactory.newDocumentBuilder();
            Document d = builder.parse(file);

            NodeList list = d.getElementsByTagName("RSAKeyValue");
            int n = list.getLength();            
            for (int i = 0; i < n; i++) {
                Node child = list.item(i);
                getNodeName(child, skey);                
            }            
            return true;
        } catch (IOException ioe) {
        	ioe.printStackTrace();
        	return false;
        } catch (SAXException saxe) {
        	saxe.printStackTrace();
        	return false;
        } catch (Exception e) {
        	e.printStackTrace();
        	return false;
        }		
	}
	
	public void getNodeName(Node parent, String skey) {
        StringBuffer sb = new StringBuffer();
        NodeList list = parent.getChildNodes();
        int n = list.getLength();
        //System.out.println("  n : " + n);
        for (int i = 0; i < n; i++) {
            Node child = list.item(i);
            String tag_name = child.getNodeName();
            if (skey.equals("private")){
	            if (tag_name.equals("Modulus")) {
	                Node content = child.getChildNodes().item(0);
	                if (content.getNodeType() == Node.TEXT_NODE) {
	                    Text text = (Text) content;
	                    private_Modulus = text.getData();
	                }
	            }
	            if (tag_name.equals("Exponent")) {
	                Node content = child.getChildNodes().item(0);
	                if (content.getNodeType() == Node.TEXT_NODE) {
	                    Text text = (Text) content;
	                    private_Exponent = text.getData();
	                }
	            }
	            if (tag_name.equals("P")) {
	                Node content = child.getChildNodes().item(0);
	                if (content.getNodeType() == Node.TEXT_NODE) {
	                    Text text = (Text) content;
	                    private_P = text.getData();
	                }
	            }
	            if (tag_name.equals("Q")) {
	                Node content = child.getChildNodes().item(0);
	                if (content.getNodeType() == Node.TEXT_NODE) {
	                    Text text = (Text) content;
	                    private_Q = text.getData();
	                }
	            }         
	            if (tag_name.equals("DP")) {
	                Node content = child.getChildNodes().item(0);
	                if (content.getNodeType() == Node.TEXT_NODE) {
	                    Text text = (Text) content;
	                    private_DP = text.getData();
	                }
	            }  
	            if (tag_name.equals("DQ")) {
	                Node content = child.getChildNodes().item(0);
	                if (content.getNodeType() == Node.TEXT_NODE) {
	                    Text text = (Text) content;
	                    private_DQ = text.getData();
	                }
	            }     
	            if (tag_name.equals("InverseQ")) {
	                Node content = child.getChildNodes().item(0);
	                if (content.getNodeType() == Node.TEXT_NODE) {
	                    Text text = (Text) content;
	                    private_InverseQ = text.getData();
	                }
	            }  
	            if (tag_name.equals("D")) {
	                Node content = child.getChildNodes().item(0);
	                if (content.getNodeType() == Node.TEXT_NODE) {
	                    Text text = (Text) content;
	                    private_D = text.getData();
	                }
	            }  
            } else {
            	if (tag_name.equals("Modulus")) {
	                Node content = child.getChildNodes().item(0);
	                if (content.getNodeType() == Node.TEXT_NODE) {
	                    Text text = (Text) content;
	                    public_Modulus = text.getData();
	                }
	            }
	            if (tag_name.equals("Exponent")) {
	                Node content = child.getChildNodes().item(0);
	                if (content.getNodeType() == Node.TEXT_NODE) {
	                    Text text = (Text) content;
	                    public_Exponent = text.getData();
	                }
	            }
            }
            
        }        
    }

	// Initializes the public and private keys.
	private void initializeKeys() {
		try {
			//Read key files back and decode them from BASE64
			readPrivateKeyFile();
			readPublicKeyFile();
			//System.out.println(privateKey.toString());
			//System.out.println(publicKey.toString());
		}catch (IOException io) {
			System.out.println("Public/ Private Key File Not found."+ io.getCause());
		}
	}
			
	public boolean verifyKey() {
		try{
			initializeKeys();
			return true;
		}catch (Exception e) {
			e.printStackTrace();
			return false;
		}		
	}  
	
	
    public static byte[] copyBytes(byte[] arr, int length){
        byte[] newArr = null;
        if (arr.length == length){
            newArr = arr;
        }else{
            newArr = new byte[length];
            for (int i = 0; i < length; i++){
                newArr[i] = (byte) arr[i];
            }
        }
        return newArr;
    }	
    
	private static byte[] decodeBASE64(String text) throws Exception {
		BASE64Decoder b64 = new BASE64Decoder();
		return b64.decodeBuffer(text);			
	}
	
    private static String encodeBASE64(byte[] bytes)
    {
        BASE64Encoder b64 = new BASE64Encoder();
        return b64.encode(bytes);
    }

	public static byte[] decrypt(byte[] text, RSAPrivateKey key) throws Exception {
        byte[] dectyptedText = null;
        try {//RSA/ECB/PKCS1Padding
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","BC");
            //logC.info("Start decryption");
            cipher.init(Cipher.DECRYPT_MODE, key);
            
            dectyptedText = cipher.doFinal(text);
        } catch (Exception e) {
            throw e;
        }
        return dectyptedText;
    }   
	
    public String decrypt(String text) throws Exception {
    	Vector<byte[]> result; 
    	result = new Vector<byte[]>();
    	int decrytedTextSize = 0;
    	byte[] decrytedTextByte = null;
    	String strResult = "failure";
        try {
			byte[] data = decodeBASE64(text);
        	byte[] buffer = new byte[_DecryptionBufferSize];
        	int pos = 0;
        	int copyLength = buffer.length;
        	while(true){
        		System.arraycopy(data, pos, buffer, 0, copyLength);
        		pos += copyLength;
        		byte[] resp = decrypt(buffer, privateKey);
        		result.addElement(resp);
        		decrytedTextSize += resp.length;
        		resp = null;            		
        		if(pos >= data.length) break;        		        		
        	}          
        	decrytedTextByte = new byte[decrytedTextSize];
        	pos = 0;
        	for(int i=0; i < result.size(); i++){
        		byte[] temp = (byte[])result.get(i);
        		int tmplen  = temp.length;
        		System.arraycopy(temp, 0, decrytedTextByte, pos, tmplen);        		
        		pos += tmplen;        		
        	}        	
        	strResult = new String(decrytedTextByte, "UTF8");
        } catch (Exception e) {
        	strResult = "failure" + e.toString();            
        }
        return strResult;
    }    
    
    public int decryptFile(String srcFileName, String destFileName) throws Exception {
        return encryptDecryptFile(srcFileName,destFileName, privateKey, Cipher.DECRYPT_MODE);
    }  
    
    public int encryptDecryptFile(String srcFileName, String destFileName, Key key, int cipherMode) throws Exception
    {
    	//StringBuffer encryptedByte = new StringBuffer();
    	//byte[] encryptedByte;
        OutputStream outputWriter = null;
        //StringBuffer sb = new StringBuffer();
        int iRet = 0;
		try
        {
        	BufferedReader br = new BufferedReader(new FileReader(srcFileName));
        	String s = "";
            String textLine;
            for(textLine = ""; (s = br.readLine()) != null; textLine = textLine + s);
            br.close();            
            if (cipherMode == Cipher.ENCRYPT_MODE) {
            	String encryptedText = encrypt(textLine);       	            	
            	outputWriter = new FileOutputStream(destFileName);            	
		        outputWriter.write(encryptedText.getBytes());
            } else {
            	String decryptedText = decrypt(textLine);
            	outputWriter = new FileOutputStream(destFileName);
				outputWriter.write(decryptedText.getBytes());
            }
            	
        }
        catch(FileNotFoundException e)
        {
            e.printStackTrace(System.err);
            iRet = -1;
        }
        catch(IOException e)
        {
            e.printStackTrace(System.err);
            iRet = -1;
        }finally{
            try {
                if (outputWriter != null) {
                    outputWriter.close();
                }
            } catch (Exception e) {
                // do nothing...
            } // end of inner try, catch (Exception)...
        }
        
        return iRet;
    }
    
    public int encryptFile(String srcFileName, String destFileName) throws Exception
    {
        return encryptDecryptFile(srcFileName,destFileName, publicKey, Cipher.ENCRYPT_MODE);
    }
    
    public static byte[] encrypt(byte[] text, RSAPublicKey key) throws Exception
    {
        byte[] cipherText = null;
        try {//RSA/ECB/PKCS1Padding
            // get an RSA cipher object and print the provider""RSA/ECB/PKCS1Padding
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","BC");
            //System.out.println(cipher.getProvider().getInfo());           
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(text);
            //System.out.println(encodeBASE64(cipherText));
        }catch (Exception e){
            throw e;
        }
        return cipherText;
    }
    
    public String encrypt(String text) throws Exception { 
    	int ciperTextSize = 0;
    	byte[] cipherText;
    	String strResult = "failure";
        try{
            byte[] dataEncoded = text.getBytes("UTF8");
            byte[] buffer = new byte[_EncryptionBufferSize];//
            int pos = 0;
        	int copyLength = buffer.length;
        	/**/
        	while(true){
        		if(pos + copyLength > dataEncoded.length){
        			copyLength = dataEncoded.length - pos;
        		}
    			buffer = new byte[copyLength];
    			System.arraycopy(dataEncoded, pos, buffer, 0, copyLength);      			
    			pos += copyLength;
    			ciperTextSize += _DecryptionBufferSize;
    			if(pos >= dataEncoded.length){
    				break;
    			}    		    			
        	}
        	
        	buffer = new byte[_EncryptionBufferSize];
            pos = 0;
        	copyLength = buffer.length;
        	int indx = 0;
            
        	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);            
            cipherText = new byte[ciperTextSize];

        	while(true){
        		if(pos + copyLength > dataEncoded.length){
        			copyLength = dataEncoded.length - pos;
        		}
    			buffer = new byte[copyLength];
    			System.arraycopy(dataEncoded, pos, buffer, 0, copyLength);      			
    			pos += copyLength;   
    			
    			byte[] ciphertemp = cipher.doFinal(buffer);  
    			System.arraycopy(ciphertemp, 0, cipherText, indx, _DecryptionBufferSize);
    			indx += ciphertemp.length;
    			if(pos >= dataEncoded.length){
    				break;
    			}     			
        	}         	
        	strResult = "success";
        }catch (Exception e){
            throw e;
        }     
        if(strResult.equalsIgnoreCase("success")){
	        String encryptedText = encodeBASE64(cipherText);
	        encryptedText = removeRetrunNew(encryptedText);
	        return encryptedText;
        }else{
        	return "failure";
        }
    }   
    
    public String removeRetrunNew(String text) throws Exception {
    	StringBuffer sb = new StringBuffer(); 
    	java.util.StringTokenizer st = new StringTokenizer(text, "\r\n");
        while(st.hasMoreTokens()){
        	String str = st.nextToken();		        	
        	sb.append(str);
        }
        return sb.toString();
    }


}