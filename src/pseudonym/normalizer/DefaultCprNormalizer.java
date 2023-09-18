package pseudonym.normalizer;

/**
 * Transform a Danish CPR number into bytes using a simple transformation, keeping only the digits (normally removing the "-").
 */
public class DefaultCprNormalizer implements Normalizer {
    public byte[] transform(String source) {
        return source.replaceAll("[^0-9]", "").getBytes();
    }
}