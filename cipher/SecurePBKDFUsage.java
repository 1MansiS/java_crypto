import java.security.SecureRandom ;
import javax.crypto.spec.PBEKeySpec ;
import javax.crypto.SecretKeyFactory ;

import java.util.Base64 ;


import java.security.spec.InvalidKeySpecException ;
import java.lang.NullPointerException ;
import java.security.spec.InvalidKeySpecException ;
import java.lang.NullPointerException ;
import java.security.NoSuchAlgorithmException ;
import java.lang.IllegalArgumentException ;
import java.security.GeneralSecurityException ;

/*
        This class shows how to use PBKDF2 based password generation.
*/
public class SecurePBKDFUsage {

        public static String PDKDF_ALGORITHM = "PBKDF2WithHmacSHA512" ;
        public static int ITERATION_COUNT = 12288 ;
        public static int SALT_LENGTH = 128 ;
        public static int DERIVED_KEY_LENGTH = 256 ;

        public static void main(String args[]) {

                // String are immutatble, so there is no way to change/nullify/modify its content after use. So always, collect and store security sensitive information in a char array instead. 
                char[] PASSWORD = args[0].toCharArray() ; 

                String hashedPassword = null ;
                try {  
                    hashedPassword = computePBKDF(PASSWORD) ;                
                } catch(GeneralSecurityException genSecExc) {System.out.println(genSecExc.getMessage() + " " + genSecExc.getCause() ) ; System.exit(1) ; } 
                
                System.out.println("PDKDF2 = " + hashedPassword) ;
        }

        public static String computePBKDF(char[] password) throws GeneralSecurityException {
                byte[] salt = new byte[SALT_LENGTH] ;
                
                SecureRandom secRandom = new SecureRandom() ;
                secRandom.nextBytes(salt) ;

                PBEKeySpec keySpec = null ;
                try { 
                    keySpec = new PBEKeySpec(password, salt, ITERATION_COUNT , DERIVED_KEY_LENGTH * 8);
                } catch(NullPointerException nullPointerExc){throw new GeneralSecurityException("Salt " + salt + "is null") ;}  
                 catch(IllegalArgumentException illegalArgumentExc){throw new GeneralSecurityException("One of the argument is illegal. Salt " + salt + " is of 0 length, iteration count " + ITERATION_COUNT + " is not positive or derived key length " + DERIVED_KEY_LENGTH + " is not positive." ) ;}  

                SecretKeyFactory pbkdfKeyFactory = null ;

                try { 
                    pbkdfKeyFactory = SecretKeyFactory.getInstance(PDKDF_ALGORITHM) ;
                } catch(NullPointerException nullPointExc) {throw new GeneralSecurityException("Specified algorithm " + PDKDF_ALGORITHM  + "is null") ;} 
                 catch(NoSuchAlgorithmException noSuchAlgoExc) {throw new GeneralSecurityException("Specified algorithm " + PDKDF_ALGORITHM + "is not available by the provider " + pbkdfKeyFactory.getProvider().getName()) ;} 
      
                byte[] pbkdfHashedArray = null ; 
                try {  
                    pbkdfHashedArray = pbkdfKeyFactory.generateSecret(keySpec).getEncoded() ; 
                } catch(InvalidKeySpecException invalidKeyExc) {throw new GeneralSecurityException("Specified key specification is inappropriate") ; } 
               
                return Base64.getEncoder().encodeToString(pbkdfHashedArray) ; 
        }
}
