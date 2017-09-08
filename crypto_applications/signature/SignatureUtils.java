package crypto_applications.signature;


import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class SignatureUtils {
    private static int FILE_READ_BUFF = 8192 ;
    private static String SHA512HASH = "SHA-256" ;




    public byte[] readFile(String fileName) throws IOException{

        Path filePath = Paths.get(fileName);
        byte[]    data = Files.readAllBytes(filePath);

        return data ;
    }

    public byte[] calculateChecksum(byte[] data) {
        MessageDigest digest = null ;

        try {
            digest = MessageDigest.getInstance(SHA512HASH) ; // Returns instance of SHA-512 implementation, from the first provider configured in java.security config file.
        } catch(NoSuchAlgorithmException nsae) {System.out.println(SHA512HASH + " not available" ); }

        digest.update(data) ;

        byte[] hash = digest.digest(); // once you have all content bundled up, than only apply digesting.

        return hash ;
    }
}
