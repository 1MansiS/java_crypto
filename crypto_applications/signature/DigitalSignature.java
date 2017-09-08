package crypto_applications.signature;


import java.io.IOException;
import java.security.*;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * This class shows how to use digital signatures. Ideally, key management systems (KMS, JKS etc), should be used to store and retrieve keys.
 * Command Line Argument, pass file name whose content needs to be digitally signed.
 */
public class DigitalSignature {

    private static String KEY_ALGO = "RSA" ;
    private static String DIGITAL_KEY_ALGO = "SHA1withRSAandMGF1" ;
    private static int DIGITAL_ALGO_KEY_LENGTH = 4096 ;
    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;




    public static void main(String[] args) throws IOException {
        String impFileName = args[0] ;
        SignatureUtils signatureUtils = new SignatureUtils() ;

        /*
        Generate public/private key pair
        Ideally, keys should be generated onces separately and stored in key management systems, and retrieved from their directly.
  */
        KeyPairGenerator keyPairGen = null;
        try {
            keyPairGen = KeyPairGenerator.getInstance(KEY_ALGO);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Algorithm " + KEY_ALGO + " not available to generate keys") ;
        }
        keyPairGen.initialize(DIGITAL_ALGO_KEY_LENGTH);

        KeyPair pair = keyPairGen.generateKeyPair() ;
        PrivateKey privateKey = pair.getPrivate() ;
        PublicKey publicKey = pair.getPublic() ;



        // Sign message checksum
        byte[] signature = new byte[8192] ;
        try {
            signature = sign(signatureUtils.calculateChecksum(signatureUtils.readFile(impFileName)) , privateKey);
        } catch(NoSuchAlgorithmException nsae) {System.out.println("Algorithm " + DIGITAL_KEY_ALGO + " not supported by any installed provider"); System.exit(0);}
        catch(InvalidKeyException ike) {System.out.println("Key Generated is not valid"); System.exit(0);}
        catch(SignatureException se) {System.out.println("Error while generating signature"); System.exit(0);}
        catch(NoSuchProviderException se) {System.out.println("Cannot find provider " + PROVIDER); System.exit(0);}

        // verify signature
        boolean verified = false ;
        try {
            verified = verify(signatureUtils.calculateChecksum(signatureUtils.readFile(impFileName)), signature, publicKey);
        } catch(NoSuchAlgorithmException nsae) {System.out.println("Algorithm " + DIGITAL_KEY_ALGO + " not supported by any installed provider"); System.exit(0);}
        catch(InvalidKeyException ike) {System.out.println("Key Generated is not valid"); System.exit(0);}
        catch(SignatureException se) {System.out.println("Error while generating signature"); System.exit(0);}
        catch(NoSuchProviderException se) {System.out.println("Cannot find provider " + PROVIDER); System.exit(0);}

        System.out.println("File checksum = " + Base64.getEncoder().encodeToString(signatureUtils.calculateChecksum(signatureUtils.readFile(impFileName))))  ;
        System.out.println("Signature Verified ? "  + verified) ;
    }

    /**
     * This method will return signature of input content (checksum), using privateKey
     * @param checksum
     * @param privateKey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private static byte[] sign(byte[] checksum, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,NoSuchProviderException {
        Signature sign = Signature.getInstance(DIGITAL_KEY_ALGO,PROVIDER) ;
        sign.initSign(privateKey);
        sign.update(checksum);

        return sign.sign() ;
    }

    /**
     * This method will verify if generated signature matches with input signature
     * @param checksum
     * @param signature
     * @param publicKey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private static boolean verify(byte[] checksum, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,NoSuchProviderException {
        Signature verify = Signature.getInstance(DIGITAL_KEY_ALGO,PROVIDER) ;
        verify.initVerify(publicKey);
        verify.update(checksum);

        return verify.verify(signature) ;
    }
}


