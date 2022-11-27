import java.util.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/*
p:= 50702342087986984684596540672785294493370824085308498450535565701730450879745310594069460940052367603038103747343106687981163754506284021184158903198888031001641800021787453760919626851704381009545624331468658731255109995186698602388616345118779571212089090418972317301933821327897539692633740906524461904910061687459642285855052275274576089050579224477511686171168825003847462222895619169935317974865296291598100558751976216418469984937110507061979400971905781410388336458908816885758419125375047408388601985300884500733923194700051030733653434466714943605845143519933901592158295809020513235827728686129856549511535000228593790299010401739984240789015389649972633253273119008010971111107028536093543116304613269438082468960788836139999390141570158208410234733780007345264440946888072018632119778442194822690635460883177965078378404035306423001560546174260935441728479454887884057082481520089810271912227350884752023760663
q:= 63762351364972653564641699529205510489263266834182771617563631363277932854227
g:= 2 
*/

public class DSA {

    // Parameters
    private static String m = "hello world";
    private static BigInteger m_hashed;

    private static VerificationKey vKey;
    private static SigningKey sKey;

    public static void main(String[] args){

        BigInteger p = new BigInteger("50702342087986984684596540672785294493370824085308498450535565701730450879745310594069460940052367603038103747343106687981163754506284021184158903198888031001641800021787453760919626851704381009545624331468658731255109995186698602388616345118779571212089090418972317301933821327897539692633740906524461904910061687459642285855052275274576089050579224477511686171168825003847462222895619169935317974865296291598100558751976216418469984937110507061979400971905781410388336458908816885758419125375047408388601985300884500733923194700051030733653434466714943605845143519933901592158295809020513235827728686129856549511535000228593790299010401739984240789015389649972633253273119008010971111107028536093543116304613269438082468960788836139999390141570158208410234733780007345264440946888072018632119778442194822690635460883177965078378404035306423001560546174260935441728479454887884057082481520089810271912227350884752023760663");
        BigInteger q = new BigInteger("63762351364972653564641699529205510489263266834182771617563631363277932854227");
        BigInteger g = new BigInteger("2");

        try{
             //1. Key Generation
            System.out.println("----------------------------------------------------------------------------------------------------------------");
            keyGeneration(p, q, g);

            //2. Signing 
            System.out.println("----------------------------------------------------------------------------------------------------------------");
            Signature signature;
            signature = signing(sKey, vKey, m);

             //3. Verification
            System.out.println("----------------------------------------------------------------------------------------------------------------");
            Verify(vKey, m_hashed, signature);
        }
        catch(NoSuchAlgorithmException e){
            System.out.println(e.getStackTrace());
        }
    }

    
    // DIGITAL SIGNATURE ALGORITHM STEPS
    //1. Key Generation
    public static void keyGeneration(BigInteger p, BigInteger q, BigInteger g){
        BigInteger h = g.modPow((p.subtract(BigInteger.ONE)).divide(q), p);

        BigInteger x = generateNum(q);

        BigInteger y = h.modPow(x, p);

        vKey = new VerificationKey(y, h, p, q);
        sKey = new SigningKey(x);

        //Output
        System.out.println("Signing:" + 
                                "\nDSA signing key (x): " + x +
                                "\nDSA verification key (vk) = (y,h,p,q):" +
                                "\n(y): " + y +
                                "\n(h): " + h +
                                "\n(p): " + p +
                                "\n(q): " + q);
    }

    //2. Signing
    public static Signature signing(SigningKey sk, VerificationKey vk, String m) throws NoSuchAlgorithmException{
        //Signing
        BigInteger k = generateNum(vk.q);

        BigInteger r = ((vk.h).modPow(k, vk.p)).mod(vk.q);

        BigInteger kprime = k.modInverse(vk.q);
        
        //Hash message 
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(m.getBytes());
        byte[] hash = messageDigest.digest();

        m_hashed = new BigInteger(1, hash);

        BigInteger s = (kprime.multiply(m_hashed.add((sk.x).multiply(r)))).mod(vk.q);

        Signature signature = new Signature(r, s);

        //Output
        System.out.println("Signing: " +
                            "\n(m_hashed): " + m_hashed +
                            "\nSecret random number (k): " + k +
                            "\nMessage to be signed (m): " + m +
                            "\nSignature (r,s):" + 
                            "\n(r): " + r +
                            "\n(s): " + s);

        return signature;
    }

    //3. Verification
    public static void Verify(VerificationKey vk, BigInteger m, Signature s){
        //3. Verification  
        BigInteger w = (s.s).modInverse(vk.q);

        BigInteger u1 = (w.multiply(m_hashed)).mod(vk.q); 
        BigInteger u2 = ((s.r).multiply(w)).mod(vk.q);
        BigInteger hu1 = vk.h.modPow(u1, vk.p);
        BigInteger yu2 = vk.y.modPow(u2, vk.p);
        BigInteger v = ((hu1.multiply(yu2)).mod(vk.p)).mod(vk.q);

        //Output
        String verificationResult = v.equals(s.r) ? "(Signature Accepted)" : "(Signature not Accepted)";
        System.out.println("Verification:" + 
                            "\n(w): " + w +
                            "\n(u1): " + u1 +
                            "\n(u2): " + u2 +
                            "\n(v): " + v +
                            "\nRESULT: " + verificationResult);

       
    }

    // HELPER METHODS --------------------------------------------------------------------------------------------

    public static BigInteger generateNum(BigInteger q){
        Random rand = new Random();

        BigInteger max = q.subtract(BigInteger.ONE);
        BigInteger min = new BigInteger("2");

        BigInteger range = (max.subtract(min));
        int len = max.bitLength();
        int bigIntegerLen = rand.nextInt(len) + 1;

        //MAX: 115792089237316195423570985008687907853269984665640564039457584007913129639936
        //MSG: 83814198383102558219731078260892729932246618004265700685467928187377105751529

        BigInteger num = new BigInteger(bigIntegerLen, rand);
        if(num.compareTo(min) < 0){
            num = num.add(min);
        }
        else if(num.compareTo(max) >= 0){
            num = num.mod(range).add(min);
        }
        return num;
    }

    public static BigInteger pow(BigInteger base, BigInteger exponent) {
        BigInteger result = BigInteger.ONE;
        while (exponent.signum() > 0) {
          if (exponent.testBit(0)) result = result.multiply(base);
          base = base.multiply(base);
          exponent = exponent.shiftRight(1);
        }
        return result;
      }

    public static int byteArrayToInt(byte[] bytes){
        return ByteBuffer.wrap(bytes).getInt();
    }

    public static final byte[] intToByteArray(int value) {
        return new byte[] {
                (byte)(value >>> 24),
                (byte)(value >>> 16),
                (byte)(value >>> 8),
                (byte)value};
    }

    // KEYS AND SIGNATURES
    // Signing Key
    static class SigningKey {
        BigInteger x;

        public SigningKey(BigInteger x) {
            this.x = x;
        }
    }

    // Verification Key
    static class VerificationKey {
        BigInteger y, h, p, q;

        public VerificationKey(BigInteger y, BigInteger h, BigInteger p, BigInteger q){
            this.y = y;
            this.h = h;
            this.p = p;
            this.q = q;
        }
    }

    // Signature
    static class Signature {
        BigInteger r, s;

        public Signature(BigInteger r, BigInteger s){
            this.r = r;
            this.s = s;
        }
    }

}
