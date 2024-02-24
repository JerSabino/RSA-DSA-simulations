
/**
 * This code is a simulation of the AES-RSA encryption/decryption process.
 * This class extends RSA to make use of its methods.
 * Simply run by running the 'main' portion of this code.
 * 
 * @author Jeremiah Sabino
 */

import java.util.*;
import java.math.BigInteger;
import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.*;
import javax.crypto.*;

public class AES_RSA extends RSA {

    private static SecretKey secretKey;
    private static IvParameterSpec ivParameter;
    private static byte[] key;

    public static void main(String[] args) {
        try {
            /*
             * KEYS -----------------------------------------------
             * Alice generates a public key and private key with RSA.
             * Bob knows Alice's public key
             */
            PublicKey pk = getPublicKey();
            PrivateKey sk = getPrivateKey();

            /* SETUP ---------------------------------------------- */
            // Generate random message
            String message = generateRandomMessage(1000000);
            System.out.println("First 32 bytes of Message: " + message.substring(0, 31) + "\n");

            // Generate AES secret key
            secretKey = generateKey(128);
            BigInteger k = stringToBigInteger(new String(secretKey.getEncoded()));
            System.out.println("Secret Key: " + k.toString(16) + "\n");

            // Generate AES iv
            ivParameter = getIV(128);

            /* ENCRYPTION ----------------------------------------- */
            // Encrypt key
            BigInteger encryptedKey = encrypt(k, pk);
            System.out.println("Encrypted Key: " + encryptedKey + "\n");

            // Encrypt Message
            String encryptedMessage = aes_encrypt(message, secretKey, ivParameter);
            System.out.println("First 32 bytes of Encrypted Message: " + encryptedMessage.substring(0, 31) + "\n");

            /* DECRYPTION ----------------------------------------- */
            // Decrypt Key
            BigInteger decryptedKey = decrypt(encryptedKey, sk);
            System.out.println("Decrypted Key: " + decryptedKey.toString(16) + "\n");

            // Decrypt Message
            String decryptedMessage = aes_decrypt(encryptedMessage, secretKey, ivParameter);
            System.out.println("First 32 bytes of Decrypted Message: " + message.substring(0, 31) + "\n");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Method for AES Encryption given a message, a secret key, and an iv
     * 
     * @param input String to be encrypted
     * @param key   The AES key
     * @param iv    The AES iv
     * @return The encrypted message
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     */
    public static String aes_encrypt(String input, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException,
            InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());

        return Base64.getEncoder()
                .encodeToString(cipherText);
    }

    /**
     * Method for AES Decryption given a cipherText, a key, and an iv
     * 
     * @param cipherText
     * @param key
     * @param iv
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     */
    public static String aes_decrypt(String cipherText, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException,
            InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));

        return new String(plainText);
    }

    /**
     * 
     * @param n
     * @return ivSpec
     */
    public static IvParameterSpec getIV(int n) {
        byte[] iv = new byte[n / 8];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(iv);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        return ivSpec;
    }

    /**
     * 
     * @param n
     * @return The secret key
     * @throws NoSuchAlgorithmException
     */
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);

        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    /**
     * 
     * @param arg
     * @return The hex representation of the given string
     */
    public static String toHex(String arg) {
        return String.format("%040x", new BigInteger(1, arg.getBytes(/* YOUR_CHARSET? */)));
    }
}
