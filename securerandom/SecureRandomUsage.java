import java.security.SecureRandom ;

public class SecureRandomUsage {

        static int NO_OF_SEED_BYTES = 20 ;

        public static void main(String args[]) {
               String random_str = new String(generateSeedBytes()) ;
               System.out.println("Random Seeded value = " + random_str) ; 
        }

        public static byte[] generateSeedBytes() {
                SecureRandom secRandom = new SecureRandom() ;
                byte[] seed_bytes = new byte[NO_OF_SEED_BYTES] ;
                secRandom.nextBytes(seed_bytes) ; // securely self-seeded 

                return seed_bytes ;
        }
}
