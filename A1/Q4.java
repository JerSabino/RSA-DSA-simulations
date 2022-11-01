import java.util.*;
import java.util.stream.*;

public class Q4 {

    private static final int ALPHABET_LEN = 26;
    private static final char FIRST_LETTER = 'A';
    private static final String CIPHER = "QAVHYFOVEDFMPBQKXNOCRGJJTZDZFDFMLNEBWFAEEXKELABKVZKTCGPOKZGZORFSEEXNBWXLKBBBRGRZMEVGSBKZIPOMYNECEFJDYXJVOBMYRFKBMRCPBKLTPPFYLPMFDLIHETHEBTUWFOVGSBPFYLPMFDTVBBJZITJGZNKVALJXUFEGHYACFOVEMVXREWVVFYZKBRYLRMYBCFMZRDTTJNGFMRYAXKKBQIBWRQLKKUPTHCNDQHHVJFDGEZSBUVYDYFBOXGUZPABTVYBTEQNLGERNQBETEEXNBWXLKBBBRMVWITXRDXEFARPBURTQMYRWXGUSPAUPGSBKZIPOPRFFPXUSZOALAEFGXULOOVFEFGXZPABTVYBLRAOLUKNTKBETMRBCQTKZDNEBKZNWPWRVWVEZSPXGUPFIMLEPTXIRCFVYNYAORETBWTRCBFFATBLNRCBIVEQLKDROXGUXYLPCRODXNNDMTJFPAWFJYQAIBFDAXRYBKRGTLGJGSBNEVGBKJVEVHWAPTUIHYPPZPVFLKUPCBIFEBGXYTPACNYDNRTPRGZIPOLZGJFGTNYXWROFQMYRQFKJGWXGXHLDXJCZHXEBYQAZFWXGUVDTHCNDQHHRJITKHHBPRXZKMYRQFKJGEBTTUTKZJBYQAVYLKWNRCBMYREBTTUTKZJBQQAVJZITJGZNBPVVX";
    private static final int KEY_LEN = 5;

    public static void main(String[] args) {
        // We split into the cipher into segments the length of the key
        List<String> segments = new ArrayList<String>();
        for (int start = 0; start < CIPHER.length(); start += KEY_LEN) {
            int end;
            if((start + KEY_LEN) < CIPHER.length())
                end = (start + KEY_LEN);
            else
                end = CIPHER.length();
            String segment = CIPHER.substring(start, end);
            segments.add(segment);
        }

        // Next, we look at the frequencies of each char for all segments per 'index'
        List<Map<Character, Integer>> charFreq = Stream.generate(HashMap<Character, Integer>::new).limit(KEY_LEN).collect(Collectors.toList());

        for (String segment : segments) {
            for (int i = 0; i < segment.length(); i++){
                char c = block.charAt(i);
                Map<Character, Integer> freq= charFreq.get(i);
                freq.compute(c, (character, f) -> f == null ? 1 : f + 1);
            }
        }

        List<List<Character, Integer>> frequencyList = new ArrayList<>();
        for (Map<Character, Integer> freq : charFreq){
            int totalNum = freq.values().stream().mapToInt(Integer::intValue).sum();
            
            List<CharacterFreq> frequencies = new ArrayList<>();
            for (Map.Entry<Character, Integer> pair : freq.entrySet()){
                double f = pair.getValue() / (double)totalNum;
                frequencies.add(new CharacterFreq(entry.getKey(), f));
            }
            Collections.sort(frequencies);
            frequencyList.add(frequencies);
        }



    }

    public String decrypt(String cipher, String key){
        StringBuilder decryptor = new StringBuilder(cipher.length());
        int index = 0;
        for (char c : cipher.toCharArray()){
            char k = key.charAt(c);

            int dCharInt = c - k;
            dCharInt = dCharInt > 0 ? dCharInt : dCharInt + ALPHABET_LEN;
            char dChar = (char)(dCharInt + 'A');
            
            decryptor.append(dChar);

            index = (index + 1) % KEY_LEN;
        }
        
        return decryptor.toString();
    }
}