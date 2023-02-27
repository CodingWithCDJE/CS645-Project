/**
 * Should print on the screen the usernames and their passwords
 * for those passwords that were found using the dictionary attack (one username and password per line), in the
 * format:
 * username:password
 *
 * @authors:
 * Christopher Estevez,
 * Shola Jolaosho,
 * Emmanuel Zongo
 */

import static crypto.MD5Shadow.crypt;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


public class Cracker {

    // We'll make a private helper function to read the shadowFile
    private static Map<String, String> readShadowFile(String fileName) throws IOException{
        Map<String, String> users = new HashMap<>();
        BufferedReader reader = new BufferedReader(new FileReader(fileName));

        String line;
        while((line = reader.readLine()) != null){
            String[] parts = line.split(":");
            String username = parts[0];
            String securedHash = parts[1];

            users.put(username, securedHash);
        }
        reader.close();
        return users;
    }

    //Another private helper function to read the commonPasswordFile
    private static Set<String> readCommonPasswords(String fileName) throws IOException{
        Set<String> passwords = new HashSet();
        BufferedReader reader = new BufferedReader(new FileReader(fileName));

        String line;
        while((line = reader.readLine()) != null){
            passwords.add(line.trim());
        }

        reader.close();
        return passwords;
    }
    public static void main(String[] args) throws IOException{
        // Read the shadow file
        Map<String, String> users = readShadowFile("shadow");

        // Read the list of common passwords
        Set<String> commonPasswords = readCommonPasswords("common-passwords.txt");

        // Check each user's password against the list of common passwords
        for(Map.Entry<String, String> entry : users.entrySet()){
            String username = entry.getKey();
            String securedHash = entry.getValue();

            String[] parts = securedHash.split("\\$");
            String salt = parts[2];
            String hash = parts[3];

            for(String password : commonPasswords){
                String testHash = crypt(password, salt);
                if(testHash.equals(hash)){
                    System.out.println(username + ":" + password);
                    break;
                }
            }
        }
    }
}