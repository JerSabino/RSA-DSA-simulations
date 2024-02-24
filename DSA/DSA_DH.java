
/**
 * This code is a simulation of the Diffie-Hellman Key Exchange (DH) algorithm to establish a secret shared key
 * in the Internet Protocol Security (IPsec) standards.
 * 
 * This simulation is between two parties: Alice and Bob
 * 
 * @author Jeremiah Sabino
 */

import java.util.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class DSA_DH extends DSA {

    public static void main(String[] args) {
        BigInteger p = new BigInteger(
                "50702342087986984684596540672785294493370824085308498450535565701730450879745310594069460940052367603038103747343106687981163754506284021184158903198888031001641800021787453760919626851704381009545624331468658731255109995186698602388616345118779571212089090418972317301933821327897539692633740906524461904910061687459642285855052275274576089050579224477511686171168825003847462222895619169935317974865296291598100558751976216418469984937110507061979400971905781410388336458908816885758419125375047408388601985300884500733923194700051030733653434466714943605845143519933901592158295809020513235827728686129856549511535000228593790299010401739984240789015389649972633253273119008010971111107028536093543116304613269438082468960788836139999390141570158208410234733780007345264440946888072018632119778442194822690635460883177965078378404035306423001560546174260935441728479454887884057082481520089810271912227350884752023760663");
        BigInteger q = new BigInteger("63762351364972653564641699529205510489263266834182771617563631363277932854227");
        BigInteger g = new BigInteger("2");

        int aliceID = 12523;
        int bobID = 51242;

        try {
            // Step 1: Alice
            // ------------------------------------------------------------------------------------------------
            BigInteger x = generateNum(q);
            BigInteger X = g.modPow(x, q);

            int T = generateSessionID();

            // Step 2: Bob
            // --------------------------------------------------------------------------------------------------
            BigInteger y = generateNum(q);
            BigInteger Y = g.modPow(y, q);

            System.out.println("DH private key for Alice x: " + x +
                    "\nDH private key for Alice y: " + y);

            // Z
            BigInteger bobZ = X.modPow(y, q);

            // Hash Z
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(bobZ.toByteArray());
            byte[] hash = messageDigest.digest();
            BigInteger hashed_z = new BigInteger(1, hash);

            // KEY 0 and KEY 1
            String key0 = "";
            String key1 = "";

            for (int i = 0; i < hashed_z.toString().length() / 2; i++) {
                key0 += hashed_z.toString().charAt(i);
            }
            for (int i = (hashed_z.toString().length() / 2); i < hashed_z.toString().length(); i++) {
                key1 += hashed_z.toString().charAt(i);
            }

            BigInteger bobk0 = new BigInteger(key0);
            BigInteger bobk1 = new BigInteger(key1);

            System.out.println("\nKeys K0 and K1 derived by Bob: " +
                    "\nK0: " + bobk0 +
                    "\nK1: " + bobk1);

            SigningKey sKeyB = generateSKey(p, q, g, y, 0);
            VerificationKey vKeyB = generateVKey(p, q, g, x, 0);

            BigInteger m = concatenate(new String[] { Integer.toString(T), hashed_z.toString() });

            // SIGNATURE
            System.out.println("\n(Signature B)");
            Signature signatureB = signing(sKeyB, vKeyB, m.toString(), 1);

            // TAG B
            messageDigest
                    .update(concatenate(new String[] { bobk1.toString(), Integer.toString(T), Integer.toString(bobID) })
                            .toByteArray());
            BigInteger tagB = new BigInteger(1, messageDigest.digest());
            System.out.println("\nTag B: " + tagB);

            // Step 3: Alice
            // --------------------------------------------------------------------------------------------------
            BigInteger aliceZ = Y.modPow(x, q);

            // Hash Z
            messageDigest.update(aliceZ.toByteArray());
            BigInteger hashed_z2 = new BigInteger(1, messageDigest.digest());

            // KEY 0 and KEY 1
            key0 = "";
            key1 = "";

            for (int i = 0; i < hashed_z2.toString().length() / 2; i++) {
                key0 += hashed_z2.toString().charAt(i);
            }
            for (int i = (hashed_z2.toString().length() / 2); i < hashed_z2.toString().length(); i++) {
                key1 += hashed_z2.toString().charAt(i);
            }

            BigInteger alicek0 = new BigInteger(key0);
            BigInteger alicek1 = new BigInteger(key1);

            System.out.println("\nKeys K0 and K1 derived by Alice: " +
                    "\nK0: " + alicek0 +
                    "\nK1: " + alicek1);

            SigningKey sKeyA = generateSKey(p, q, g, y, 0);
            VerificationKey vKeyA = generateVKey(p, q, g, x, 0);

            BigInteger m2 = concatenate(new String[] { Integer.toString(T), hashed_z2.toString() });

            // SIGNATURE
            System.out.println("\n(Signature A)");
            Signature signatureA = signing(sKeyA, vKeyA, m2.toString(), 1);
            BigInteger tagprime;

            // TAG A
            messageDigest.update(
                    concatenate(new String[] { alicek1.toString(), Integer.toString(T), Integer.toString(aliceID) })
                            .toByteArray());
            BigInteger tagA = new BigInteger(1, messageDigest.digest());
            System.out.println("\nTag A: " + tagA);

            // TAG VERIFY
            messageDigest.update(
                    concatenate(new String[] { alicek1.toString(), Integer.toString(T), Integer.toString(bobID) })
                            .toByteArray());
            tagprime = new BigInteger(1, messageDigest.digest());

            System.out.println("\n(Verifying Tag B == Tag')" +
                    "\nTag': " + tagprime);
            if (tagprime.equals(tagB)) {
                System.out.println("(TAG B VERIFIED)");
            } else {
                System.out.println("TAGS NOT EQUAL");
            }

            // Step 4: Bob
            // --------------------------------------------------------------------------------------------------
            // TAG VERIFY
            messageDigest.update(
                    concatenate(new String[] { bobk1.toString(), Integer.toString(T), Integer.toString(aliceID) })
                            .toByteArray());
            tagprime = new BigInteger(1, messageDigest.digest());

            System.out.println("\n(Verifying Tag A == Tag')" +
                    "\nTag': " + tagprime);
            if (tagprime.equals(tagA)) {
                System.out.println("(TAG A VERIFIED)");
            } else {
                System.out.println("TAGS NOT EQUAL");
            }

        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getStackTrace());
        }

    }

    public static BigInteger concatenate(String[] arr) {
        String s = "";
        for (int i = 0; i < arr.length; i++) {
            s += arr[i];
        }
        return new BigInteger(s);
    }

    public static int generateSessionID() {
        Random rn = new Random();
        int i = rn.nextInt(100 - 1 + 1) + 1;

        return i;
    }

}
