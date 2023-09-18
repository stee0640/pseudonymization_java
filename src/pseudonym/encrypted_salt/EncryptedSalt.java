package pseudonym.encrypted_salt;

import java.security.SecureRandom;
import java.util.HexFormat;

import pseudonym.encryption.AesGcm;

/**
 * Representation of an encrypted project specific salt used for generating pseudonyms
 */
public class EncryptedSalt
{
    static final int NONCE_BYTES = 12;
    static final int SECRET_SALT_BYTES = 16;
    static final int TAG_BYTES = 16;

    private byte[] nonce;
    private byte[] secret_salt; // including tag
 
    final SecureRandom secure_random = new SecureRandom();
    final HexFormat hex_format = HexFormat.of();

    /**
     * Constructor initializing the member byte sequences with zeroes
     */
    public EncryptedSalt()
    {
        nonce = new byte[NONCE_BYTES];
        secret_salt = new byte[SECRET_SALT_BYTES + TAG_BYTES];
    }

    /**
     * Encrypt and store a new salt.
     * 
     * @param encryption_key the key used for encrypting the salt
     * @param secret_salt the salt to encrypt
     * @return the EncryptedSalt instance
     */
    public EncryptedSalt encrypt(byte[] encryption_key, byte[] secret_salt)
    {
        this.secure_random.nextBytes(this.nonce);
        this.secret_salt = new AesGcm(encryption_key, this.nonce).encrypt(secret_salt);
        return this;
    }

    /**
     * Decrypt a stored salt.
     * 
     * @param encryption_key the key used when the salt was encrypted
     * @return the decrypted salt stored in this EncryptedSalt instance
     */
    public byte[] decrypt(byte[] encryption_key)
    {
        return new AesGcm(encryption_key, this.nonce).decrypt(this.secret_salt);
    }

    /**
     * Generate, encrypt and store a new salt.
     * 
     * @param encryption_key the key used for encrypting the salt
     * @return the EncryptedSalt instance
     */
    public EncryptedSalt generate(byte[] encryption_key)
    {
        this.secure_random.nextBytes(this.secret_salt);
        this.encrypt(encryption_key, this.secret_salt);
        return this;
    }

    /**
     * Dump the EncryptedSalt instance as a hex string.
     * 
     * @return a hex string consisting of NONCE + ENCRYPTED_SALT + TAG
     */
    public String dump() {
        return hex_format.formatHex(this.nonce) + hex_format.formatHex(this.secret_salt);
    }

    /**
     * Load the EncryptedSalt instance from a hex string.
     * 
     * @param serialized_encrypted_salt a hex string containing the encrypted salt as NONCE + ENCRYPTED_SALT + TAG
     * @return the EncryptedSalt instance
     */
    public EncryptedSalt load(String serialized_encrypted_salt) {
        // Multiplications by 2 below because a byte is represented as 2 hex characters. 
        String nonce_string = serialized_encrypted_salt.substring(0, NONCE_BYTES * 2);
        String secret_salt_string = serialized_encrypted_salt.substring(NONCE_BYTES * 2, SECRET_SALT_BYTES * 2 + TAG_BYTES * 2);
        this.nonce = hex_format.parseHex(nonce_string);
        this.secret_salt = hex_format.parseHex(secret_salt_string);
        return this;
    }

}