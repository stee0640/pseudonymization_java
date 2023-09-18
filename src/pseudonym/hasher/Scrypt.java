package pseudonym.hasher;

import org.bouncycastle.crypto.generators.SCrypt;

/**
 * Derive a salted hash using scrypt
 */
public class Scrypt implements Hasher {
    public byte[] hash(byte[] plaintext, byte[] salt) {
        return SCrypt.generate(plaintext, salt, 16384, 8, 1, 32);
    }
    
}
