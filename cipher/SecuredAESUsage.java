import javax.crypto.Cipher ;
import java.security.SecureRandom ;
import javax.crypto.spec.IvParameterSpec ;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec ;

import java.util.Base64 ;

import java.security.NoSuchAlgorithmException ;
import java.security.InvalidKeyException;
import javax.crypto.IllegalBlockSizeException ;
import javax.crypto.NoSuchPaddingException ;
import java.security.InvalidAlgorithmParameterException ;
import javax.crypto.BadPaddingException ;

public class SecuredAESUsage {
        public static void main(String args[]) {
                String messageToEncrypt = args[0] ;

                /*
                        Make sure to use different Key + IV pair for multiple plain text data.
                */
                // Generating Key
                SecretKey aesKey = null ;
                try {
                    KeyGenerator keygen = KeyGenerator.getInstance("AES") ; // Specifying algorithm key will be used for 
                    keygen.init(256) ; // Specifying Key size to be used, Note: This would need JCE Unlimited Strength to be installed explicitly 
                    aesKey = keygen.generateKey() ;
                } catch(NoSuchAlgorithmException noSuchAlgoExc) { System.out.println("Key being request is for AES algorithm, but this cryptographic algorithm is not available in the environment "  + noSuchAlgoExc) ; System.exit(1) ; } 

                // Generating IV
                byte iv[] = new byte[16];
                SecureRandom secRandom = new SecureRandom() ;
                secRandom.nextBytes(iv); // SecureRandom initialized using self-seeding

                String encryptedText = aesEncrypt(messageToEncrypt, aesKey, iv) ;
                String decryptedText = aesDecrypt(Base64.getDecoder().decode(encryptedText), aesKey, iv) ; // Same key and IV for decryption as used for encryption.

                System.out.println("Encrypted text = " + encryptedText) ;

                System.out.println("Decrytped Text = " + decryptedText) ;

        }

        public static String aesEncrypt(String message, SecretKey aesKey, byte[] aesIV) {
                Cipher c = null ;
                try { 
                    c = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Transformation specifies algortihm, mode of operation and padding

                } catch(NoSuchAlgorithmException noSuchAlgoExc) {System.out.println("Exception while encrypting. Algorithm being requested is not available in this environment " + noSuchAlgoExc); System.exit(1); } 
                 catch(NoSuchPaddingException noSuchPaddingExc) {System.out.println("Exception while encrypting. Padding Scheme being requested is not available this environment " + noSuchPaddingExc); System.exit(1); } 

                IvParameterSpec randomIvSpec = new IvParameterSpec(aesIV) ; // IV created using secure self-seeded SecureRandom object

                try { 
                    c.init(Cipher.ENCRYPT_MODE, aesKey, randomIvSpec, new SecureRandom()) ;
                } catch(InvalidKeyException invalidKeyExc) {System.out.println("Exception while encrypting. Key being used is not valid. It could be due to invalid encoding, wrong length or uninitialized " + invalidKeyExc) ; System.exit(1); } 
                 catch(InvalidAlgorithmParameterException invalidAlgoParamExc) {System.out.println("Exception while encrypting. Algorithm parameters being specified are not valid " + invalidAlgoParamExc) ; System.exit(1); } 

                byte[] cipherTextInByteArr = null ;
                try { 
                    cipherTextInByteArr = c.doFinal(message.getBytes()) ;
                } catch(IllegalBlockSizeException illegalBlockSizeExc) {System.out.println("Exception while encrypting, due to block size " + illegalBlockSizeExc) ; System.exit(1); } 
                 catch(BadPaddingException badPaddingExc) {System.out.println("Exception while encrypting, due to padding scheme " + badPaddingExc) ; System.exit(1); } 

                return Base64.getEncoder().encodeToString(cipherTextInByteArr);
        }

        public static String aesDecrypt(byte[] encryptedMessage, SecretKey aesKey, byte[] aesIV) {
               Cipher c = null ;

               try { 
                   c = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Transformation specifies algortihm, mode of operation and padding
                } catch(NoSuchAlgorithmException noSuchAlgoExc) {System.out.println("Exception while decrypting. Algorithm being requested is not available in environment " + noSuchAlgoExc); System.exit(1); } 
                 catch(NoSuchPaddingException noSuchAlgoExc) {System.out.println("Exception while decrypting. Padding scheme being requested is not available in environment " + noSuchAlgoExc); System.exit(1); } 

               IvParameterSpec randomIvSpec = new IvParameterSpec(aesIV) ; // IV created using secure self-seeded SecureRandom object. Same IV used for encrypting 

               try { 
                   c.init(Cipher.DECRYPT_MODE, aesKey, randomIvSpec, new SecureRandom()) ; 
                } catch(InvalidKeyException invalidKeyExc) {System.out.println("Exception while decryption. Key being used is not valid " + invalidKeyExc); System.exit(1); } 
                 catch(InvalidAlgorithmParameterException invalidKeyExc) {System.out.println("Exception while decryption. Algorithm Parameters being used are not valid " + invalidKeyExc); System.exit(1); } 

                byte[] plainTextInByteArr = null ;
                try { 
                    plainTextInByteArr = c.doFinal(encryptedMessage) ; 
                } catch(IllegalBlockSizeException illegalBlockSizeExc) {System.out.println("Exception while decryption, due to block size " + illegalBlockSizeExc) ; System.exit(1); } 
                 catch(BadPaddingException badPaddingExc) {System.out.println("Exception while decryption, due to padding scheme " + badPaddingExc) ; System.exit(1); } 

               return new String(plainTextInByteArr) ;
        }
}
