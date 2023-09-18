package pseudonym.pseudonymizer;

import pseudonym.encrypted_salt.EncryptedSalt;
import pseudonym.hasher.Hasher;
import pseudonym.hasher.Scrypt;
import pseudonym.normalizer.DefaultCprNormalizer;
import pseudonym.normalizer.Normalizer;

/**
 * Class that handles the transformation of plaintext to a pseudonym using a
 * configurable normalizer and hasher.
 */
public class Pseudonymizer {
    private final byte[] salt;
    private final Normalizer normalizer;
    private final Hasher hasher;

    static final int SECRET_SALT_BYTES = 16;

    /**
     * Constructor for configuring a specific normalizer and hasher
     * 
     * @param serialized_encrypted_salt project specific encrypted salt
     * @param storage_key key for decrypting the salt
     * @param normalizer an instance of a class implementing the normalizer interface
     * @param hasher an instance of a class implementing the hasher interface
     * 
     */
    public Pseudonymizer(String serialized_encrypted_salt, byte[] storage_key, Normalizer normalizer, Hasher hasher) {
        this.salt = getSalt(serialized_encrypted_salt, storage_key);
        this.normalizer = normalizer;
        this.hasher = hasher;
    }

    /**
     * Constructor for using the default normalizer (CPR) and hasher (scrypt)
     * 
     * @param serialized_encrypted_salt project specific encrypted salt
     * @param storage_key key for decrypting the salt
     */
    public Pseudonymizer(String serialized_encrypted_salt, byte[] storage_key) {
        this.salt = getSalt(serialized_encrypted_salt, storage_key);
        this.normalizer = new DefaultCprNormalizer();
        this.hasher = new Scrypt();
    }

    /*
     * In the Java implementation of AES/GCM encryption, salt and tag are stored in
     * the same byte structure.
     * This private method is used to just get the salt bytes and drop the tag.
     */
    private byte[] getSalt(String serialized_encrypted_salt, byte[] storage_key) {
        byte[] salt_and_tag = new EncryptedSalt().load(serialized_encrypted_salt).decrypt(storage_key);
        byte[] salt = new byte[SECRET_SALT_BYTES];
        System.arraycopy(salt_and_tag, 0, salt, 0, SECRET_SALT_BYTES);
        return salt;
    }

    /**
     * Generate a pseudonym from plaintext
     * 
     * @param plaintext the string to pseudonymize
     * @return the pseudonym as a sequence of bytes
     */
    public byte[] pseudonym(String plaintext) {
        return this.hasher.hash(this.normalizer.transform(plaintext), this.salt);
    }
}
