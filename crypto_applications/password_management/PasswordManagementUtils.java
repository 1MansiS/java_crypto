package crypto_usecases.password_management;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordManagementUtils {
        
    public String PDKDF_ALGORITHM = "PBKDF2WithHmacSHA512" ;
    public int ITERATION_COUNT = 12288 ;
    public int SALT_LENGTH = 128 ;
    public int DERIVED_KEY_LENGTH = 256 ;
    
    
    protected byte[] generateEncryptedPassword(String enteredPassword, byte[] salt) throws GeneralSecurityException {
             // Strings are immutatable, so there is no way to change/nullify/modify its content after use. So always, collect and store security sensitive information in a char array instead. 
            char[] charEnteredPassword = enteredPassword.toCharArray() ;
            
            PBEKeySpec keySpec = null ;
            
            try {
                    keySpec = new PBEKeySpec(charEnteredPassword, salt, ITERATION_COUNT, DERIVED_KEY_LENGTH * 8 ) ;
            } catch(NullPointerException npe) {throw new GeneralSecurityException("Salt " + returnStringRep(salt) + "is null") ;}
            catch(IllegalArgumentException iae) {throw new GeneralSecurityException("One of the argument is illegal. Salt " + returnStringRep(salt) + " may be of 0 length, iteration count " + ITERATION_COUNT + " is not positive or derived key length " + DERIVED_KEY_LENGTH + " is not positive." ) ;}
            
            SecretKeyFactory pbkdfKeyFactory = null ;
            
            try {
                    pbkdfKeyFactory = SecretKeyFactory.getInstance(PDKDF_ALGORITHM) ;
            } catch(NullPointerException nullPointExc) {throw new GeneralSecurityException("Specified algorithm " + PDKDF_ALGORITHM  + "is null") ;}
            catch(NoSuchAlgorithmException noSuchAlgoExc) {throw new GeneralSecurityException("Specified algorithm " + PDKDF_ALGORITHM + "is not available by the provider " + pbkdfKeyFactory.getProvider().getName()) ;}

            byte[] pbkdfHashedArray = null ;
            try {
                    pbkdfHashedArray = pbkdfKeyFactory.generateSecret(keySpec).getEncoded() ;
            }catch(InvalidKeySpecException invalidKeyExc) {throw new GeneralSecurityException("Specified key specification is inappropriate") ; }
            
            return pbkdfHashedArray;
    }
        
    protected String returnStringRep(byte[] data) {
                return Base64.getEncoder().encodeToString(data) ;
    }
    
    protected byte[] returnByteArray(String data) {
                return Base64.getDecoder().decode(data) ;
    }
}
