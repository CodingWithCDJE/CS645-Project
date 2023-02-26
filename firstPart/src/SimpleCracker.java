/**
 * A java program that determines whether the shadow file contains any
 * commonly used passwords
 *
 * @authors:
 * Christopher Estevez,
 * Shola Jolaosho,
 * Emmanuel Zongo
 */
import java.math.BigInteger;
import java.io.*;
import java.security.*;

public class SimpleCracker {

    public static String toHex(byte[] bytes){
        BigInteger bi = new BigInteger(1, bytes);
        return String.format("%0" + (bytes.length << 1) + "X", bi);
    }

    public static void main(String[] args) throws Exception{
        // Read the common password file
        BufferedReader commonPasswordsFileReader = new BufferedReader(new FileReader("common-passwords.txt"));

       // Read the shadow file
        BufferedReader shadowFileReader = new BufferedReader(new FileReader("shadow-simple"));



        // Next is to loop through each line in the common password file
        String commonPasswordRow;
        while((commonPasswordRow = commonPasswordsFileReader.readLine()) != null){
            // After determing that theirs a line to be read, we'll begin to loop through the shadow file
            String shadowRow;
            while((shadowRow = shadowFileReader.readLine()) != null){
                // Start to split the shadow row string into the three components that each row contains based on the :
                String[] shadowComponents = shadowRow.split(":");
                String username = shadowComponents[0];
                String salt = shadowComponents[1];
                String hashedHex = shadowComponents[2];

                // Obtaining the cryptographic hash of the current common password and the salt using MessageDigest
                byte[] hashedBytes = MessageDigest.getInstance("MD5").digest((salt + commonPasswordRow).getBytes());
                String computedHashedHex = toHex(hashedBytes);

                // Now it's time to check whether the cryptographic hashed we just computed is the same one from the shadowFile
                if(computedHashedHex.equals(hashedHex)){
                    // Should print on the screen the username and their password
                    // Format: username:password
                    System.out.println(username + ":" + commonPasswordRow);
                }

            }
            // After we have gone through the entire shadowFile we want to close it and re-assign it to the variable from the start
            shadowFileReader.close();
            shadowFileReader = new BufferedReader(new FileReader("shadow-simple"));
        }
    // After we have fully gone through the commonPasswordFile and shadowFile
        // We'll close both files
        shadowFileReader.close();
        commonPasswordsFileReader.close();
    }


}





