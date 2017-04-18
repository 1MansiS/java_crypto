import java.security.KeyPairGenerator;
import java.security.PrivateKey ;
import java.security.PublicKey ;
import java.util.Base64 ;;
import javax.crypto.Cipher ;
import java.lang.Exception ;
import java.security.Key ;
import java.security.KeyPair ;

public class SecuredRSAUsage {

        static int RSA_KEY_LENGTH = 4096;
        static String ALGORITHM_NAME = "RSA" ;
        static String PADDING_SCHEME = "OAEPWITHSHA-512ANDMGF1PADDING" ;
        static String MODE_OF_OPERATION = "ECB" ; // This essentially means none behind the scene

        public static void main(String args[]) {
                String shortMessage = args[0] ;


                try {

                // Generate Key Pairs
                KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance(ALGORITHM_NAME) ;
                rsaKeyGen.initialize(RSA_KEY_LENGTH) ;
                KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair() ;


                    String encryptedText = rsaEncrypt(shortMessage, rsaKeyPair.getPublic());

                    String decryptedText = rsaDecrypt(Base64.getDecoder().decode(encryptedText), rsaKeyPair.getPrivate()) ;

                    System.out.println("Encrypted text = " + encryptedText) ;
                    System.out.println("Decrypted text = " + decryptedText) ;

                } catch(Exception e) {System.out.println("Exception while encryption/decryption") ;e.printStackTrace() ; } 

                
        }

        public static String rsaEncrypt(String message, Key publicKey) throws Exception {
        
                Cipher c = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME) ;

                c.init(Cipher.ENCRYPT_MODE, publicKey) ;

                byte[] cipherTextArray = c.doFinal(message.getBytes()) ;

                return Base64.getEncoder().encodeToString(cipherTextArray) ;
                
        }


        public static String rsaDecrypt(byte[] encryptedMessage, Key privateKey) throws Exception {
                Cipher c = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME) ;
                c.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] plainText = c.doFinal(encryptedMessage);

                return new String(plainText) ;

        }
}
