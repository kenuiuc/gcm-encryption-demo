package com.ken.encryption.kmsRestClient;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Objects;

import static com.ken.encryption.kmsRestClient.EncryptionUtils.*;

@Slf4j
public class EncryptionUtilsTest {

    @BeforeEach
    public void init() {
    }

    @Test
    public void dataKeyLength256() {
        String dataKeyBase64 = Constants.dataKeyBase64;
        byte[] dataKey = Base64.getDecoder().decode(dataKeyBase64);
        Assertions.assertEquals(32, dataKey.length);
    }

    @Test
    public void encryptDecrypt() throws Exception {
        log.debug("msgText = {}", Constants.MSG_EN);
        final byte[] msg = utf8Encode(Constants.MSG_EN);
        log.debug("msg.length = {}", msg.length);
        final byte[] dataKey = base64Decode(Constants.dataKeyBase64);
        log.debug("dataKey.length = {}", dataKey.length);
        final byte[] encryptedPayload = encrypt(dataKey, msg);
        log.debug("encryptedPayload.length = {}", encryptedPayload.length);
        final byte[] encryptedMsg = getEncryptedMsg(encryptedPayload);
        Assertions.assertTrue(ArrayUtils.isSameLength(msg, encryptedMsg));
        final byte[] decryptedMsg = decrypt(dataKey, encryptedPayload);
        Assertions.assertArrayEquals(msg, decryptedMsg);
        log.debug("decryptedMsgText = {}", utf8Decode(decryptedMsg));
    }

    @Test
    public void dontRepeatCipherText() throws Exception {
        final byte[] msg = utf8Encode(Constants.MSG_CN);
        final byte[] dataKey = base64Decode(Constants.dataKeyBase64);

        final byte[] encryptedPayloadOne = encrypt(dataKey, msg);
        final byte[] gcmIVOne = getIV(encryptedPayloadOne);
        final byte[] encryptedMsgOne = getEncryptedMsgWithAuthTag(encryptedPayloadOne);
        final byte[] tagOne = getAuthTag(encryptedPayloadOne);

        final byte[] encryptedPayloadTwo = encrypt(dataKey, msg);
        final byte[] gcmIVTwo = getIV(encryptedPayloadTwo);
        final byte[] encryptedMsgTwo = getEncryptedMsgWithAuthTag(encryptedPayloadTwo);
        final byte[] tagTwo = getAuthTag(encryptedPayloadTwo);

        Assertions.assertTrue(ArrayUtils.isSameLength(encryptedMsgOne, encryptedMsgTwo));
        Assertions.assertFalse(Objects.deepEquals(gcmIVOne, gcmIVTwo));
        Assertions.assertFalse(Objects.deepEquals(encryptedMsgOne, encryptedMsgTwo));
        Assertions.assertFalse(Objects.deepEquals(tagOne, tagTwo));

        final byte[] decryptedMsgOne = decrypt(dataKey, encryptedPayloadOne);
        final byte[] decryptedMsgTwo = decrypt(dataKey, encryptedPayloadTwo);

        Assertions.assertTrue(Objects.deepEquals(decryptedMsgOne, decryptedMsgTwo));
    }

}
