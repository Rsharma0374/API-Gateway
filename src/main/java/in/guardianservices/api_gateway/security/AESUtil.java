package in.guardianservices.api_gateway.security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

public class AESUtil {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";


    // Store key in a secure vault instead of cache (only for demo purposes)
    private static final ConcurrentHashMap<String, Object> CACHE = new ConcurrentHashMap<>();


    // Generate a random AES-256 key
    public static String generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    // Encrypt
    public static String encrypt(String plainText, String key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM);

        // Generate a random IV (16 bytes)
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Concatenate IV + Encrypted data and encode in Base64
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    // Decrypt
    public static String decrypt(String encryptedText, String key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM);

        byte[] combined = Base64.getDecoder().decode(encryptedText);
        byte[] iv = new byte[16];
        byte[] encryptedBytes = new byte[combined.length - 16];

        // Extract IV and encrypted text
        System.arraycopy(combined, 0, iv, 0, iv.length);
        System.arraycopy(combined, iv.length, encryptedBytes, 0, encryptedBytes.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }


}
