package pseudonym.encryption;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Class wrapping AES/GCM encryption in Java to be compatible with similar implementations in other languages
 */
public class AesGcm {

    private Cipher cipher;

    public AesGcm(byte[] key, byte[] iv) {
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        try {
            this.cipher = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); // 128 bit auth tag length
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    /**
     * Encrypt plaintext using AES/GCM
     * 
     * @param plaintext the byte sequence to encrypt
     * @return encrypted byte sequence
     */
    public byte[] encrypt(byte[] plaintext) {
        byte[] ciphertext = null;
        try {
            ciphertext = this.cipher.doFinal(plaintext);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return ciphertext;
    }

    /**
     * Decrypt ciphertext using AES/GCM
     * 
     * @param ciphertext the byte sequence to decrypt
     * @return the decrypted byte sequence
     */
    public byte[] decrypt(byte[] ciphertext) {
        byte[] plaintext = null;
        try {
            plaintext = this.cipher.doFinal(ciphertext);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return plaintext;
    }
 
}
