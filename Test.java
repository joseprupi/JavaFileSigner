package JavaFileSigner;

import java.util.logging.Level;
import java.util.logging.Logger;

public class Test {

    public static void main(String[] args) {
        try {
            
            FileSigner fs = new FileSigner();
            
            fs.generateKeys(1024, "RSA");
            fs.saveKeys("public.txt", "private.txt");
            fs.readKeys("public.txt", "private.txt");
            fs.sign("input.txt", "signed.txt");
            System.out.println(fs.verify("input.txt", "signed.txt"));
            
        } catch (Exception ex) {
           System.out.println(ex.getMessage());
        }
    }
}
