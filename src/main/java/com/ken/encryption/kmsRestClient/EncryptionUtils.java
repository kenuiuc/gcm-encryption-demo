package com.ken.encryption.kmsRestClient;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

@Slf4j
public class EncryptionUtils {

    private static final int GCM_IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BYTES = 16;
    private static final int GCM_TAG_LENGTH_BITS = GCM_TAG_LENGTH_BYTES * 8;

    /**
     * // TODO: which signature algo its using by default?
     * Encryption with ALG_AES_256_GCM_IV12_TAG16_NO_KDF
     * <p>
     * See <a href="https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html">Encryption Algorithms</a>
     * @param dataKey AES-256 key
     * @param msg plaintext message
     * @return encrypted payload in the format of cat[randomIV, encryptedMsg, authTag]
     * @throws Exception
     */
    public static byte[] encrypt(byte[] dataKey, byte[] msg) throws Exception {
        final byte[] gcmIV = utf8Encode(getRandomChars(GCM_IV_LENGTH_BYTES));
        log.debug("gcmIV.length = {}", gcmIV.length);
        final SecretKeySpec keySpec = new SecretKeySpec(dataKey, "AES");
        final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, gcmIV);
        Cipher encipher = Cipher.getInstance("AES/GCM/NoPadding");
        encipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        byte[] encryptedMsgWithAuthTag = encipher.doFinal(msg);
        log.debug("encryptedMsgWithAuthTag.length = {}", encryptedMsgWithAuthTag.length);
        byte[] payload = ArrayUtils.addAll(gcmIV, encryptedMsgWithAuthTag);
        log.debug("payload.length = {}", payload.length);
        return payload;
    }

    /**
     * Decryption with ALG_AES_256_GCM_IV12_TAG16_NO_KDF
     * <p>
     * See <a href="https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html">Encryption Algorithms</a>
     * @param dataKey AES-256 key
     * @param payload encrypted payload in the format of cat[randomIV, encryptedMsg, authTag]
     * @return decrypted message
     * @throws Exception
     */
    public static byte[] decrypt(byte[] dataKey, byte[] payload) throws Exception {
        final byte[] gcmIV = getIV(payload);
        final byte[] encryptedMsgWithAuthTag = getEncryptedMsgWithAuthTag(payload);
        log.debug("encryptedMsgWithAuthTag.length = {}", encryptedMsgWithAuthTag.length);
        final SecretKeySpec keySpec = new SecretKeySpec(dataKey, "AES");
        final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, gcmIV);
        Cipher decipher = Cipher.getInstance("AES/GCM/NoPadding");
        decipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        byte[] msg = decipher.doFinal(encryptedMsgWithAuthTag);
        return msg;
    }


    public static byte[] getIV (byte[] payload) {
        return Arrays.copyOfRange(payload, 0, GCM_IV_LENGTH_BYTES);
    }
    public static byte[] getEncryptedMsgWithAuthTag(byte[] payload) {
        return Arrays.copyOfRange(payload, GCM_IV_LENGTH_BYTES, payload.length);
    }
    public static byte[] getEncryptedMsg(byte[] payload) {
        return Arrays.copyOfRange(payload, GCM_IV_LENGTH_BYTES, payload.length - GCM_TAG_LENGTH_BYTES);
    }
    public static byte[] getAuthTag(byte[] payload) {
        return Arrays.copyOfRange(payload, payload.length - GCM_TAG_LENGTH_BYTES, payload.length);
    }
    public static String base64Encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
    public static byte[] base64Decode(final String base64String) {
        return Base64.getDecoder().decode(base64String);
    }
    public static byte[] utf8Encode(final String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
    public static String utf8Decode(final byte[] utf8Bytes) {
        return new String(utf8Bytes, StandardCharsets.UTF_8);
    }

    public static String getRandomChars(int length) {
        StringBuilder randomCharsBuf = new StringBuilder(1024);
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < length; i++) {
            if (random.nextInt(2) % 2 == 0) {
                int letterIndex = random.nextInt(2) % 2 == 0 ? 65 : 97;
                randomCharsBuf.append((char) (random.nextInt(26) + letterIndex));
            } else {
                randomCharsBuf.append(random.nextInt(10));
            }
        }
        return randomCharsBuf.toString();
    }
}
