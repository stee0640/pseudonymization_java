package pseudonym.storage_password;

import java.nio.charset.StandardCharsets;

import pseudonym.hasher.Hasher;
import pseudonym.hasher.Scrypt;

/**
 * Class for deriving the storage key from a password using scrypt.
 */
public class StoragePassword {
    private byte[] storage_key_salt;

    private Hasher hasher;

    /**
     * Constructor using scrypt as kdf when deriving a key from a password
     * @param storage_key_salt the salt for use when deriving the key
     */
    public StoragePassword(byte[] storage_key_salt) {
        this.storage_key_salt = storage_key_salt;
        this.hasher = new Scrypt();
    }

    /**
     * 
     * @param password the storage password to derive a key from
     * @return the storage key
     */
    public byte[] derive_key(String password) {
        return this.hasher.hash(password.getBytes(StandardCharsets.UTF_8), this.storage_key_salt);
    }
 }
