package ru.zeker.common.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public final class HmacUtil {
    private HmacUtil(){}

    public static String sign (String data, String secret, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), algorithm);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(secretKeySpec);
        byte[] rawHmac = mac.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(rawHmac);
    }

    public static boolean verify(String data, String signature, String secret, String algorithm)
            throws InvalidKeyException, NoSuchAlgorithmException {

        String expectedSignature = sign(data, secret, algorithm);
        return expectedSignature.equals(signature);
    }
}
