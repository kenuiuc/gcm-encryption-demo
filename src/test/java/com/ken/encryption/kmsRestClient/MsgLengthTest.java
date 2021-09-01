package com.ken.encryption.kmsRestClient;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import static com.ken.encryption.kmsRestClient.EncryptionUtils.*;

@Slf4j
public class MsgLengthTest {

    @Test
    public void encryptEnMsg() throws Exception {
        String msgStr = Constants.MSG_EN;
        log.info("EN msgStr.length = {}", msgStr.length());
        encryptMsg(msgStr);
    }

    @Test
    public void encryptCnMsg() throws Exception {
        String msgStr = Constants.MSG_CN;
        log.info("CN msgStr.length = {}", msgStr.length());
        encryptMsg(msgStr);
    }

    private void encryptMsg(String msgStr) throws Exception {
        byte[] dataKey = base64Decode(Constants.dataKeyBase64);
        byte[] msg = utf8Encode(msgStr);
        byte[] payload = encrypt(dataKey, msg);
        byte[] encryptedMsg = getEncryptedMsg(payload);
        String encryptedMsgBase64 = base64Encode(encryptedMsg);
        String encryptedMsgUtf8 = utf8Decode(encryptedMsg);
        log.info("msg.bytes = {}, encryptedMsg.bytes = {}, encryptedMsgBase64String.chars = {}, "
                        + "encryptedMsgUtf8String.chars = {}",
            msg.length, encryptedMsg.length, encryptedMsgBase64.length(), encryptedMsgUtf8.length()
        );
        Assertions.assertEquals(msg.length, encryptedMsg.length);
    }
}
