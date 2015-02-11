package com.acme.corp;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.time.DateUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.Date;

/**
 * This demo app posts some data to the Microsoft Service Bus / EventHub
 */
public class AzureEventHubPost {

    // the namespace of your azure service bus; ex. https://acme-ns.servicebus.windows.net
    private static String azureNamespace = "https://acme-ns.servicebus.windows.net";

    // the name of your azure eventhub;
    private static String azureEventhub = "acme";

    // azure keyname
    private static String azureKeyName = "RootManageSharedAccessKey";

    // azure keyvalue
    private static String azureKeyValue = "zBNsdfdfsddsfdsf952121xxcvcseewrer=";

    // payload that is submitted to azure eventhub
    private static String payload = "{'test':'test'}";

    public static void main(String[] args) {
        CloseableHttpClient httpclient = HttpClients.createDefault();

        try {
            // construct the url on which data gets posted
            HttpPost httpPost = new HttpPost(azureNamespace + "/"+ azureEventhub + "/messages");

            // create sas token
            String token = createSasToken(azureNamespace, azureKeyName, azureKeyValue);

            // add the token to the header of the request
            httpPost.addHeader("Authorization", token);
            httpPost.addHeader(HttpHeaders.CONTENT_TYPE, "application/atom+xml");
            httpPost.setEntity(new StringEntity(payload));

            // execute the request
            CloseableHttpResponse response = httpclient.execute(httpPost);

            // print out the response
            System.out.println("Response: " + response.getStatusLine());
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (ClientProtocolException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Calculates a sas token with default expirytime of 1 hour!
     *
     * @param uri the namespace of your Microsoft EventHub (ex. https://<namespace>.servicebus.windows.net)
     * @param keyName the name of your key
     * @param keyValue the value of the key
     * @return a SAS token
     */
    static private String createSasToken(String uri, String keyName, String keyValue) {

        Calendar cal = Calendar.getInstance(); // creates calendar
        cal.setTime(new Date()); // sets calendar time/date
        cal.add(Calendar.HOUR_OF_DAY, 1 ); // adds one hour
        Date expiry = cal.getTime();
        expiry = DateUtils.round(expiry, Calendar.MINUTE);

        try {
            String stringToSign = URLEncoder.encode(uri, "UTF-8") + "\n" + expiry.getTime()/1000;

            String hash = generateHashAsBase64(stringToSign, keyValue);

            return "SharedAccessSignature sr=" + URLEncoder.encode(uri,"UTF-8") + "&sig=" + URLEncoder.encode(hash, "UTF-8") + "&se=" + expiry.getTime()/1000 + "&skn=" + keyName;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }


    static private String generateHashAsBase64(String input, String signKey) {
        return Base64.encodeBase64String(generateHash(input, signKey, "HmacSHA256"));
    }

    /**
     * Generates a security hash
     * @param input the data that needs to be hashed
     * @param key the key that is used to construct the hash
     * @param hashMethod the hash method according to javax.crypto.Mac (HmacMD5, HmacSHA1 or HmacSHA256)
     * @return the bytes of the hash, these can be encoded as needed
     */
    static private byte[] generateHash(String input, String key, String hashMethod) {
        // Get an hmac_sha1 key from the raw key bytes
        byte[] keyBytes = key.getBytes();
        SecretKeySpec signKey = new SecretKeySpec(keyBytes, hashMethod);

        Mac mac = null;
        try {
            mac = Mac.getInstance(hashMethod);
            mac.init(signKey);
            return mac.doFinal(input.getBytes());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }
}