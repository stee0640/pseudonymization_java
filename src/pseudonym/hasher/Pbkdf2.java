package pseudonym.hasher;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Derive a salted hash using PBKDF2 (PKCS#5) with SHA256.
 */
public class Pbkdf2 implements Hasher {

    /**
     * Wrap the PKCS5 generator.
     * 
     * @param password password for derived key
     * @param salt salt for derived key
     * @param iterations the "cost" when deriving the key
     * @param keySizeInBytes number of bytes in the derived key
     * @return the derived key
     */
    private static byte[] deriveKey(byte[] password, byte[] salt, int iterations, int keySizeInBytes) {
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
        generator.init(password, salt, iterations);
        KeyParameter keyParameter = (KeyParameter) generator.generateDerivedParameters(keySizeInBytes * 8);

        return keyParameter.getKey();
    }

    public byte[] hash(byte[] plaintext, byte[] salt) {
        return deriveKey(plaintext, salt, 100000, 32);
    }
}
