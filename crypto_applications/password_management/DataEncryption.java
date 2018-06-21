package crypto_applications.password_management;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.regex.Pattern;

public class DataEncryption {
    public static void main(String[] args) {
        if (args.length < 3) {
            System.err.println("Missing arguments. Usage: java DataEncryption encrypt password salt < file");
            System.exit(1);
        }
        String output = "";
        char[] password = args[1].toCharArray();
        String salt = args[2];
        try {
            String input = readStdIn();

            if (args[0].equals("encrypt")) {
                output = encrypt(input, password, salt);
            } else if (args[0].equals("decrypt")) {
                output = decrypt(input, password, salt);
            } else {
                System.err.println("Invalid operation, first argument must be 'encrypt' or 'decrypt'");
                System.exit(1);
            }
        } catch (GeneralSecurityException e) {
            e.printStackTrace(System.err);
            System.exit(1);
        }

        System.out.println(output);
    }

    private static String encrypt(String data, char[] password, String salt) throws GeneralSecurityException {
        PasswordManagementUtils utils = new PasswordManagementUtils();

        KeySpec spec = new PBEKeySpec(password);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithHmacSHA512AndAES_128");
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(tmp.getEncoded(), "PBEWithHmacSHA512AndAES_128");

        byte iv[] = new byte[16];

        SecureRandom secRandom = new SecureRandom() ;
        secRandom.nextBytes(iv); // self-seeded randomizer to generate IV

        IvParameterSpec randomIvSpec = new IvParameterSpec(iv) ;

        PBEParameterSpec pbeSpec = new PBEParameterSpec(salt.getBytes(), 4096, randomIvSpec);
        Cipher c = Cipher.getInstance("PBEWITHHMACSHA512ANDAES_128");
        c.init(Cipher.ENCRYPT_MODE, secret, pbeSpec);
        byte[] encrypted = c.doFinal(data.getBytes());

        return utils.returnStringRep(encrypted) + "$" + utils.returnStringRep(iv);
    }

    private static String decrypt(String data, char[] password, String salt) throws GeneralSecurityException {
        PasswordManagementUtils utils = new PasswordManagementUtils();

        String[] dataParts = data.split(Pattern.quote("$"));
        if (dataParts.length != 2) {
            throw new GeneralSecurityException("Data does not contain IV?");
        }
        byte[] encrypted = utils.returnByteArray(dataParts[0].trim());
        byte[] iv = utils.returnByteArray(dataParts[1].trim());

        KeySpec spec = new PBEKeySpec(password);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithHmacSHA512AndAES_128");
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(tmp.getEncoded(), "PBEWithHmacSHA512AndAES_128");

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        PBEParameterSpec pbeSpec = new PBEParameterSpec(salt.getBytes(), 4096, ivSpec);
        Cipher c = Cipher.getInstance("PBEWITHHMACSHA512ANDAES_128");
        c.init(Cipher.DECRYPT_MODE, secret, pbeSpec);

        return new String(c.doFinal(encrypted));
    }

    private static String readStdIn() throws GeneralSecurityException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[32 * 1024];

        try {
            int bytesRead;
            while ((bytesRead = System.in.read(buffer)) > 0) {
                baos.write(buffer, 0, bytesRead);
            }
            return baos.toString();
        } catch (IOException e) { throw new GeneralSecurityException("Unable to read stdin"); }
    }
}
