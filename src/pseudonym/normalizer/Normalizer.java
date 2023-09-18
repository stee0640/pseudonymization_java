package pseudonym.normalizer;

/**
 * Interface for normalizing and transforming a source string to bytes
 */
public interface Normalizer {

    /**
     * Transform a string to a normalized sequence of bytes
     * @param source source string
     * @return the transformed source as a byte sequence
     */
    byte[] transform(String source);
}
