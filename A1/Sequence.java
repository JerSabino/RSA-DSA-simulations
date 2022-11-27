/* 
 * Theory Assignment 3b)
 * Written code used to compute the first 31 bits of the sequence
 * @author Jeremiah Sabino
 */
import java.util.*;

public class Sequence {

    public static void main(final String[] args) {
        int[] seq = new int[31];
        seq[0] = 1;
        seq[1] = 0;
        seq[2] = 1;
        seq[3] = 0;
        seq[4] = 1;

        for(int i = 0; i < 25; i++){
            int index = 5 + i;
            int result = (seq[i] + seq[i+4] + seq[i+2] + seq[i+1]) % 2;
            seq[index] = result;
        }

        int numOnes = 0;
        int numZeros = 0;
        System.out.println("Sequence: ");
        for(int i = 0; i < seq.length; i++){
            System.out.print(seq[i]);

            if(seq[i] == 1){
                numOnes++;
            }
            else if(seq[i] == 0){
                numZeros++;
            }
        }
        System.out.println("\n# of ones: " + numOnes + "\n# of zeros: " + numZeros);

    }

}