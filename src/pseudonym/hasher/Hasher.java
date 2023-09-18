package pseudonym.hasher;

/**
 * Interfaced for deriving a salted hash from a plaintext.
 */
public interface Hasher {
    /**
     * Derive a salted hash from the plaintext.
     * 
     * @param plaintext plaintext to derive a salted hash from
     * @param salt salt for the hashing algorithm
     * @return the salted hash value
     */
    byte[] hash(byte[] plaintext, byte[] salt);
}
