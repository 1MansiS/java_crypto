package crypto_applications.mac;


import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import java.util.Arrays;


/**
 * This class shows how to use HMAC. Ideally, separate key management systems would be used for storing and retrieving of secret keys.
 */
public class MacComputation {

    private static String HMAC_ALGORITHM = "HmacSHA256" ;

    public static void main(String args[]) throws IOException{
        String fileNameToBeMaced = args[0] ;

        // Some checks for validity of file, existence, null, file extn etc

        MacUtils macUtils = new MacUtils();

        // generate secret key for MAC computation
        KeyGenerator kg = null;
        try {
            kg = KeyGenerator.getInstance(HMAC_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
           System.out.println("Unable to generate key for " + HMAC_ALGORITHM);
           System.exit(0);
        }
        SecretKey secretKey = kg.generateKey() ;

        byte[] macTag = sender(macUtils.readFile(fileNameToBeMaced), secretKey) ;

        System.out.println("Receiver verified integrity and authenticity of message from file " + fileNameToBeMaced + " ? " + macVerifiedByReceiver(macUtils.readFile(fileNameToBeMaced), macTag, secretKey)) ;

    }

    /**
     * This method is used on sender side, to compute MacTag and send it across to receiver, alongwith original message content,  to verify against recomputed MacTag
     * @param content
     * @param secretKey
     * @return
     */
    private static byte[] sender(byte[] content, SecretKey secretKey) {
        return computeMac(content, secretKey);
    }

    /**
     * This method is used on receiver side, to recompute macTag, and verify it with send macTag. This will verify integrity and authenticity of received messages.
     * @param content
     * @param macTag
     * @param secretKey
     * @return
     */
    private static boolean macVerifiedByReceiver(byte[] content, byte[] macTag, SecretKey secretKey) {
        byte[] recomputerMacTags = computeMac(content, secretKey) ;

        boolean isVerified = false ;

        if(Arrays.equals(macTag, recomputerMacTags))
            isVerified = true;

        return isVerified ;

    }


    /**
     * This method, would be available both on sender and receiver side. This will compute macTag of input message, using same SecretKey on both sides.
     * @param content
     * @param secretKey
     * @return
     */
    private static byte[] computeMac(byte[] content, SecretKey secretKey) {

        Mac mac = null;
        try {
            mac = Mac.getInstance(HMAC_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No algorithm found for MAC using " + HMAC_ALGORITHM) ;
            System.exit(0);
        }
        try {
            mac.init(secretKey);
        } catch (InvalidKeyException e) {
            System.out.println("Generated key is invalid") ;
            System.exit(0);
        }

        mac.update(content);

        return mac.doFinal() ;
    }

}
