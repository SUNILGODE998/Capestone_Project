package com.capestone.login.Util;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class PasswordDecryptor {
    private static final String SECRET_KEY = "12345678901234567890123456789012"; // 32 chars for AES-256 // 16 chars for AES-128 // 32 chars for AES-256
    private static final String INIT_VECTOR = "1234567890123456"; // 16 chars for AES-CBC IV

    public static String decrypt(String encryptedPassword) throws Exception {
        byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        byte[] ivBytes = INIT_VECTOR.getBytes(StandardCharsets.UTF_8);

        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}