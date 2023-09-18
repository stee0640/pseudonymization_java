package pseudonym.normalizer;

/**
 * The null normalizer encodes the source string without transformation (except defdault encoding)
 */
public class NullNormalizer implements Normalizer {
    public byte[] transform(String source) {
        return source.getBytes();
    }
}
