/*
 * CS4355 Programming Assignment 1
 * This code is a simulation of RSA encryption/decryption process.
 * Simply run by running the 'main' portion of this code. 
 * 
 * @author Jeremiah Sabino - 3621717
 */
import java.util.*;
import java.math.BigInteger;

public class RSA {

    //Large primes
    private static BigInteger p = new BigInteger("19211916981990472618936322908621863986876987146317321175477459636156953561475008733870517275438245830106443145241548501528064000686696553079813968930084003413592173929258239545538559059522893001415540383237712787805857248668921475503029012210091798624401493551321836739170290569343885146402734119714622761918874473987849224658821203492683692059569546468953937059529709368583742816455260753650612502430591087268113652659115398868234585603351162620007030560547611");
    private static BigInteger q = new BigInteger("49400957163547757452528775346560420645353827504469813702447095057241998403355821905395551250978714023163401985077729384422721713135644084394023796644398582673187943364713315617271802772949577464712104737208148338528834981720321532125957782517699692081175107563795482281654333294693930543491780359799856300841301804870312412567636723373557700882499622073341225199446003974972311496703259471182056856143760293363135470539860065760306974196552067736902898897585691");

    //Composite modulus
    private static BigInteger n = p.multiply(q);

    //Phi
    private static BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

    //Encryption Exponents
    private static BigInteger e = generateE(phi);

    //Decryption Exponent
    private static BigInteger d = e.modInverse(phi);

    public static void main(String[] args){
        //Public and Private Keys
        PublicKey publicKey =  getPublicKey();
        PrivateKey privateKey = getPrivateKey();

        //Encryption
        String randomMessage = generateRandomMessage(100); //Generate random plaintext
        BigInteger message = stringToBigInteger(randomMessage); //Convert plaintext to BigInteger
        BigInteger ciphertext = encrypt(message, publicKey); //Encrypt message to ciphertext
        
        //Decrypts cipher and calculates elapsed time w/o CRT
        long startTime = System.nanoTime();
        BigInteger decryptedMessage = decrypt(ciphertext, privateKey); //Decrypt cipher to message
        long endTime = System.nanoTime();
        long elapsedTime = (endTime - startTime)/1000000; //Conversion of nanotime to milliseconds

        //Decryption with Chinese Remainder Theorem 
        // m = mp * q * qprime + mq * p *  pprime mod n
        BigInteger qprime = q.modInverse(p); //q'
        BigInteger pprime = p.modInverse(q); //p'
        BigInteger dp = d.mod(p.subtract(BigInteger.ONE)); 
        BigInteger dq = d.mod(q.subtract(BigInteger.ONE)); 

        long startTime2 = System.nanoTime(); //Include computation of cp, cq, mp, mq in elapsed time
        BigInteger cp = ciphertext.mod(p);
        BigInteger cq = ciphertext.mod(q);
        BigInteger mp = cp.modPow(dp, p);
        BigInteger mq = cq.modPow(dq, q);
        
        BigInteger decryptedMessageCRT = decryptCRT(ciphertext, new BigInteger[] {qprime, pprime, q, p, mp, mq, n});
        long endTime2 = System.nanoTime();
        long elapsedTime2 = (endTime2 - startTime2)/1000000; //Conversion of nanotime to miliseconds

        //OUTPUT
        System.out.println("RSA SIMULATION"
                            + "\n------------------------------------------------------------------------------------------------------------"
                            + "\nThe first prime is p = " + p 
                            + "\n\nThe second prime is q = " + q
                            + "\n\nThe composite modulus is n = " + n
                            + "\n\nThe encryption exponent is e = " + e
                            + "\n\nThe decryption exponent is d = " + d
                            + "\n\nCheck (e*d mod phi): " + (e.multiply(d)).mod(phi)
                            + "\n------------------------------------------------------------------------------------------------------------"
                            + "\nMessage: " + randomMessage
                            + "\n------------------------------------------------------------------------------------------------------------"
                            + "\nCiphertext: " + ciphertext
                            + "\n------------------------------------------------------------------------------------------------------------"
                            + "\nDecrypted Message: " + decryptedMessage
                            + "\nDecrypted Message in plaintext: " + bigIntegerToString(decryptedMessage)
                            + "\n\nDecryptedCRT Message: " + decryptedMessageCRT
                            + "\nDecryptedCRT Message in plaintext: " + bigIntegerToString(decryptedMessageCRT)
                            + "\n------------------------------------------------------------------------------------------------------------"
                            + "\nCOMPUTATION TIME: "
                            + "\nComputation time of decryption: " + elapsedTime + "ms"
                            + "\nComputation time of decryption with CRT: " + elapsedTime2 + "ms");
    }

    //ENCRYPTION -----------------------------------------------------------
    /*
     * Converts a String message to BigInteger
     */
    public static BigInteger stringToBigInteger(String msg){
        String cipher = "";
        int i = 0;
        while (i < msg.length()){
            int c = (int) msg.charAt(i);
            cipher += c;
            i++;
        }
        BigInteger convertedCipher = new BigInteger(String.valueOf(cipher));
        return convertedCipher;
    }

    /*
     * Encryption:
     * c = m^e mod n
     */
    public static BigInteger encrypt(BigInteger msg, PublicKey p){
        return msg.modPow(p.e, p.n);
    }

    //DECRYPTION -----------------------------------------------------------
    /*
     * Converts a BigInteger to a String message
     */
    public static String bigIntegerToString(BigInteger cipher){
        String cipherString = cipher.toString();
        String message = "";
        int i = 0;
        while (i < cipherString.length()){
            int t = Integer.parseInt(cipherString.substring(i, i+2));
            char c = (char) t;
            message += c;
            i += 2;
        }
        return message;
    }

    /*
     * Decryption: 
     * m'= cˆd mod n
     */
    public static BigInteger decrypt(BigInteger cipher, PrivateKey p){
        return cipher.modPow(p.d, (p.p).multiply(p.q));
    }

    /*
     * Decryption using CRT: 
     * m = mp * q * qprime + mq * p * pprime mod n
     * val = {qprime, pprime, q, p, mp, mq, n}
     *          0       1     2  3  4   5   6
     */
    public static BigInteger decryptCRT(BigInteger cipher, BigInteger[] vals){
        BigInteger a = (vals[4].multiply(vals[2]).multiply(vals[0])); //mp * q * qprime 
        BigInteger b = (vals[5].multiply(vals[3]).multiply(vals[1])); //mq * p * pprime

        return (a.add(b)).mod(vals[6]); //(a + b) mod n
    }

    //HELPER METHODS -----------------------------------------------------------
    /*
     * Generates an e such that e * d mod phi = 1
     */
    public static BigInteger generateE(BigInteger phi){
        Random random = new Random();
        BigInteger e = new BigInteger(1024, random);

        while(!getGCD(e, phi).equals(BigInteger.ONE)){
            e = new BigInteger(1024, random);
            while(e.min(phi).equals(phi)){
                e = new BigInteger(1024, random);
            }
        }

        return e;
    }

    /*
     * Gets the greatest common divisor of a and b 
     */
    public static BigInteger getGCD(BigInteger a, BigInteger b){
        if (!b.equals(BigInteger.ZERO)){
            return getGCD(b, a.mod(b));
        }
        else{
            return a;
        }
    }

    /* 
     * Generates a random alphabetic message of length 50 to 100
     */
    public static String generateRandomMessage(int length){
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        StringBuilder builder = new StringBuilder();

        Random random = new Random();
        while(builder.length() < length){
            int i = (int) (random.nextFloat() * chars.length());
            builder.append(chars.charAt(i));
        }
        String message = builder.toString();
        return message;
    }

    //KEYS --------------------------------------------------------------------
    /* 
     *  Public Key = (e, n)
     */
    static class PublicKey {
        BigInteger e, n;

        public PublicKey(BigInteger e, BigInteger n){
            this.e = e;
            this.n = n;
        }
    }

    /* 
     *  Private Key = (d, p, q)
     */
    static class PrivateKey {
        BigInteger d, p, q;

        public PrivateKey(BigInteger d, BigInteger p, BigInteger q){
            this.d = d;
            this.p = p;
            this.q = q;
        }
    }

    public static PublicKey getPublicKey() {
        return new PublicKey(e, n);
    }

    public static PrivateKey getPrivateKey() {
        return new PrivateKey(d, p, q);
    }
}




