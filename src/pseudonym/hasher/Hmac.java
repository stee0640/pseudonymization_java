package pseudonym.hasher;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Hmac implements Hasher {

    public byte[] hash(byte[] plaintext, byte[] salt) {
        String algorithm = "HmacSHA256";
        byte[] result = null;
        SecretKeySpec secretKeySpec = new SecretKeySpec(salt, algorithm);
        Mac mac;
        try {
            mac = Mac.getInstance(algorithm);
            mac.init(secretKeySpec);
            result = mac.doFinal(plaintext);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return result;
    }
}
