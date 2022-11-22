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
    private static BigInteger p = new BigInteger("50702342087986984684596540672785294493370824085308498450535565701730450879745310594069460940052367603038103747343106687981163754506284021184158903198888031001641800021787453760919626851704381009545624331468658731255109995186698602388616345118779571212089090418972317301933821327897539692633740906524461904910061687459642285855052275274576089050579224477511686171168825003847462222895619169935317974865296291598100558751976216418469984937110507061979400971905781410388336458908816885758419125375047408388601985300884500733923194700051030733653434466714943605845143519933901592158295809020513235827728686129856549511535000228593790299010401739984240789015389649972633253273119008010971111107028536093543116304613269438082468960788836139999390141570158208410234733780007345264440946888072018632119778442194822690635460883177965078378404035306423001560546174260935441728479454887884057082481520089810271912227350884752023760663");
    private static BigInteger q = new BigInteger("63762351364972653564641699529205510489263266834182771617563631363277932854227");
    private static BigInteger g = new BigInteger("2");

    private static String m = "Message to be encrypted";

    public static void main(String[] args) throws NoSuchAlgorithmException{

        //Key Generation 
        BigInteger h = g.modPow((p.subtract(BigInteger.ONE)).divide(q), p);

        BigInteger x = new BigInteger("1234");

        BigInteger y = h.modPow(x, p);

        VerificationKey vKey = new VerificationKey(y, h, p, q);
        SigningKey sKey = new SigningKey(x);

        //Signing
        BigInteger k = new BigInteger("3");

        BigInteger r = (h.modPow(k, p)).mod(q);

        BigInteger kprime = k.modInverse(q);
        
        //Hash message 
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(m.getBytes(StandardCharsets.UTF_8));
        byte[] hash = messageDigest.digest();

        int hashed = byteArrayToInt(hash);
        BigInteger m_hashed = new BigInteger(Integer.toString(hashed));
        BigInteger s = (kprime.multiply(m_hashed.add(x.multiply(r)))).mod(q);

        Signature signature = new Signature(r, s);
        
        //Verification  
        BigInteger w = s.modInverse(q);

        BigInteger u1 = (w.multiply(m_hashed)).mod(q); 
        BigInteger u2 = (r.multiply(w)).mod(q);

        //Debugging
        System.out.println("H: " + h + 
                            "\nY: " + y + 
                            "\nX: " + x + 
                            "\nK: " + k + 
                            "\nhashed: " + hashed + 
                            "\nm_hashed: " + m_hashed + 
                            "\nS: " + s +
                            "\nW: " + w + 
                            "\nu1: " + u1 + 
                            "\nu2: " + u2 + 
                            "\nr: " + r);
    }

    public static BigInteger generateNum(){
        Random rand = new Random();

        BigInteger max = q.subtract(BigInteger.ONE);
        BigInteger min = new BigInteger("2");

        BigInteger range = (max.subtract(min));
        int len = max.bitLength();

        BigInteger num = new BigInteger(len, rand);
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

    static class SigningKey {
        BigInteger x;

        public SigningKey(BigInteger x) {
            this.x = x;
        }
    }

    static class VerificationKey {
        BigInteger y, h, p, q;

        public VerificationKey(BigInteger y, BigInteger h, BigInteger p, BigInteger q){
            this.y = y;
            this.h = h;
            this.p = p;
            this.q = q;
        }
    }

    static class Signature {
        BigInteger r, s;

        public Signature(BigInteger r, BigInteger s){
            this.r = r;
            this.s = s;
        }
    }

}
