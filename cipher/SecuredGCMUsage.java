import javax.crypto.Cipher ;
import java.security.SecureRandom ;
import javax.crypto.spec.GCMParameterSpec ;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.util.Base64 ;

import java.security.NoSuchAlgorithmException ;
import java.security.InvalidKeyException;
import javax.crypto.IllegalBlockSizeException ;
import javax.crypto.NoSuchPaddingException ;
import java.security.InvalidAlgorithmParameterException ;
import javax.crypto.BadPaddingException ;
import javax.crypto.ShortBufferException;

public class SecuredGCMUsage {

        public static void main(String args[]) {
                String messageToEncrypt = args[0] ;
                
                byte[] aadData = "random".getBytes() ;

                // Use different key+IV pair for encrypting/decrypting different parameters
                // Generating Key
                SecretKey aesKey = null ;
                try {
                    KeyGenerator keygen = KeyGenerator.getInstance("AES") ; // Specifying algorithm key will be used for 
                    keygen.init(256) ; // Specifying Key size to be used, Note: This would need JCE Unlimited Strength to be installed explicitly 
                    aesKey = keygen.generateKey() ;
                } catch(NoSuchAlgorithmException noSuchAlgoExc) { System.out.println("Key being request is for AES algorithm, but this cryptographic algorithm is not available in the environment "  + noSuchAlgoExc) ; System.exit(1) ; }

                // Generating IV
                byte iv[] = new byte[96];
                SecureRandom secRandom = new SecureRandom() ;
                secRandom.nextBytes(iv); // SecureRandom initialized using self-seeding

                // Initialize GCM Parameters
                GCMParameterSpec gcmParamSpec = new GCMParameterSpec(128, iv) ;      
                
                byte[] encryptedText = aesEncrypt(messageToEncrypt, aesKey,  gcmParamSpec, aadData) ;          
                //String encryptedText = aesEncrypt(messageToEncrypt, aesKey,  gcmParamSpec, aadData) ;          

                //System.out.println("Encryped text " + Base64.getDecoder().decode(encryptedText).length + " encryptedText " + encryptedText) ;                
                String decryptedText = aesDecrypt(encryptedText, aesKey, gcmParamSpec, aadData) ; // Same key and IV for decryption as used for encryption.
                //String decryptedText = aesDecrypt(Base64.getDecoder().decode(encryptedText), aesKey, gcmParamSpec, aadData) ; // Same key and IV for decryption as used for encryption.

                System.out.println("Decrypted text " + decryptedText) ;
        }


        public static byte[] aesEncrypt(String message, SecretKey aesKey, GCMParameterSpec gcmParamSpec, byte[] aadData) {
        //public static String aesEncrypt(String message, SecretKey aesKey, GCMParameterSpec gcmParamSpec, byte[] aadData) {
                Cipher c = null ;

                try {
                        c = Cipher.getInstance("AES/GCM/PKCS5Padding"); // Transformation specifies algortihm, mode of operation and padding
                }catch(NoSuchAlgorithmException noSuchAlgoExc) {System.out.println("Exception while encrypting. Algorithm being requested is not available in this environment " + noSuchAlgoExc); System.exit(1); }
                 catch(NoSuchPaddingException noSuchPaddingExc) {System.out.println("Exception while encrypting. Padding Scheme being requested is not available this environment " + noSuchPaddingExc); System.exit(1); }

                
                try {
                    c.init(Cipher.ENCRYPT_MODE, aesKey, gcmParamSpec, new SecureRandom()) ;
                } catch(InvalidKeyException invalidKeyExc) {System.out.println("Exception while encrypting. Key being used is not valid. It could be due to invalid encoding, wrong length or uninitialized " + invalidKeyExc) ; System.exit(1); }
                 catch(InvalidAlgorithmParameterException invalidAlgoParamExc) {System.out.println("Exception while encrypting. Algorithm parameters being specified are not valid " + invalidAlgoParamExc) ; System.exit(1); }

                try { 
                    c.updateAAD(aadData) ;
                }catch(IllegalArgumentException illegalArgumentExc) {System.out.println("Exception thrown while encrypting. Byte array might be null " +illegalArgumentExc ); System.exit(1);} 
                catch(IllegalStateException illegalStateExc) {System.out.println("Exception thrown while encrypting. CIpher is in an illegal state " +illegalStateExc); System.exit(1);} 
                catch(UnsupportedOperationException unsupportedExc) {System.out.println("Exception thrown while encrypting. Provider might not be supporting this method " +unsupportedExc); System.exit(1);} 
               byte[] cipherTextInByteArr = null ;
               //byte[] cipherTextInByteArr = new byte[c.getOutputSize(message.getBytes().length)]; ;
               try {
                    cipherTextInByteArr = c.doFinal(message.getBytes()) ;
                    //c.doFinal(message.getBytes(), 0, message.getBytes().length, cipherTextInByteArr) ;
               } catch(IllegalBlockSizeException illegalBlockSizeExc) {System.out.println("Exception while encrypting, due to block size " + illegalBlockSizeExc) ; System.exit(1); }
                 catch(BadPaddingException badPaddingExc) {System.out.println("Exception while encrypting, due to padding scheme " + badPaddingExc) ; System.exit(1); }
                 //catch(ShortBufferException shortBufferExc) {System.out.println("Exception while encrypting, due to short buffer length" + shortBufferExc) ; System.exit(1); }

               return cipherTextInByteArr ;
               //return Base64.getEncoder().encodeToString(cipherTextInByteArr);
        }


        public static String aesDecrypt(byte[] encryptedMessage, SecretKey aesKey, GCMParameterSpec gcmParamSpec, byte[] aadData) {
               Cipher c = null ;
        
               try {
                   c = Cipher.getInstance("AES/GCM/PKCS5Padding"); // Transformation specifies algortihm, mode of operation and padding
                } catch(NoSuchAlgorithmException noSuchAlgoExc) {System.out.println("Exception while decrypting. Algorithm being requested is not available in environment " + noSuchAlgoExc); System.exit(1); }
                 catch(NoSuchPaddingException noSuchAlgoExc) {System.out.println("Exception while decrypting. Padding scheme being requested is not available in environment " + noSuchAlgoExc); System.exit(1); }  

                try {
                    c.init(Cipher.ENCRYPT_MODE, aesKey, gcmParamSpec, new SecureRandom()) ;
                } catch(InvalidKeyException invalidKeyExc) {System.out.println("Exception while encrypting. Key being used is not valid. It could be due to invalid encoding, wrong length or uninitialized " + invalidKeyExc) ; System.exit(1); }
                 catch(InvalidAlgorithmParameterException invalidParamSpecExc) {System.out.println("Exception while encrypting. Algorithm Param being used is not valid. " + invalidParamSpecExc) ; System.exit(1); }

                try {
                    c.updateAAD(aadData) ;
                }catch(IllegalArgumentException illegalArgumentExc) {System.out.println("Exception thrown while encrypting. Byte array might be null " +illegalArgumentExc ); System.exit(1);}
                catch(IllegalStateException illegalStateExc) {System.out.println("Exception thrown while encrypting. CIpher is in an illegal state " +illegalStateExc); System.exit(1);}

                byte[] plainTextInByteArr = null ;
                try {
                    plainTextInByteArr = c.doFinal(encryptedMessage) ;
                } catch(IllegalBlockSizeException illegalBlockSizeExc) {System.out.println("Exception while decryption, due to block size " + illegalBlockSizeExc) ; System.exit(1); }
                 catch(BadPaddingException badPaddingExc) {System.out.println("Exception while decryption, due to padding scheme " + badPaddingExc) ; System.exit(1); }

                System.out.println("Length of plain text array " + plainTextInByteArr.length) ;

                return new String(plainTextInByteArr) ;
        }
}
