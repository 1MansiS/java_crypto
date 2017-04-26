package message_digest;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest ;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class CalculateChecksum {

	public static String SHA512HASH = "SHA-512" ;
	
	public static int FILE_READ_BUFF = 8192 ; 
	
    public static void main(String args[]) {
        
    	String fileName = args[0] ;
        // Should perform some file validation, like length check, null check etc.
    	System.out.println(SHA512HASH + " checksum = " + getChecksum(fileName)) ;
    }
    
    // Returns Base64 encoded checksum value of input file.
    public static String getChecksum(String fileName) {
    	MessageDigest digest = null ;    	
    	byte[] buffer = new byte[8192] ; // read 8192 bytes at a time
    	BufferedInputStream bis = null ;
    	int count ;
    	
    	try {
    		digest = MessageDigest.getInstance(SHA512HASH) ; // Returns instance of SHA-512 implementation, from the first provider configured in java.security config file.
    	} catch(NoSuchAlgorithmException nsae) {System.out.println(SHA512HASH + " not available" ); }
    	
    	try {
    		bis = new BufferedInputStream(new FileInputStream(fileName)) ;
    		while((count = bis.read()) > 0) {
        		digest.update(buffer,0,count) ; // repeated apply update method, till all content of this file is bundled up for digesting
        	}
    	} catch(IOException io) {System.out.println(io.getMessage());}	
    	
    	byte[] hash = digest.digest(); // once u have all content bundled up, than only apply digesting.
    	
    	return Base64.getEncoder().encodeToString(hash) ; // to return in a human readable format
    	
    }
}
