package JavaFileSigner;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.FileWriter ;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.util.io.pem.PemObject;

public class FileSigner{
    
    public void generateKeys(int size, String keyAlgo)
    throws NoSuchAlgorithmException {
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgo);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(size, random);
       
        this.keyAlgo = keyGen.getAlgorithm();
        
        switch (this.keyAlgo) {
            case "DSA":
                this.signAlgo = "SHA1withDSA";
                break;
            case "RSA":
                this.signAlgo = "SHA1withRSA";
                break;
            default:
                break;
        }
        
        this.keyPair = keyGen.generateKeyPair();
       
    }
    public void sign(String ﬁleName, String ﬁleOut ) throws Exception{
        
        String provider;
        
        if("DSA".equals(this.keyAlgo)){
            provider = "SUN";
        }else{
            provider = "SunJSSE";
        }
        
        Signature sig = Signature.getInstance(this.signAlgo, provider);
        
        sig.initSign(this.keyPair.getPrivate());
        
        FileInputStream fis = new FileInputStream(ﬁleName);
        BufferedInputStream bufin = new BufferedInputStream(fis);
        byte[] buffer = new byte[1024];
        int len;
        while ((len = bufin.read(buffer)) >= 0) {
            sig.update(buffer, 0, len);
        }
        bufin.close();
        
        FileOutputStream fos = new FileOutputStream(ﬁleOut);
        BufferedOutputStream bufout = new BufferedOutputStream(fos);
        
        byte[] realSig = sig.sign();
        fos.write(realSig);
        
        bufout.close();
        
    }
    public boolean verify(String ﬁleName, String signature) throws Exception{
        
        FileInputStream sigfis = new FileInputStream(signature);
        byte[] sigToVerify = new byte[sigfis.available()]; 
        sigfis.read(sigToVerify);
        sigfis.close();
        
        String provider;
        
        if("DSA".equals(this.keyAlgo)){
            provider = "SUN";
        }else{
            provider = "SunJSSE";
        }
        
        Signature sig = Signature.getInstance(this.signAlgo, provider);
        
        sig.initVerify(this.keyPair.getPublic());
        
        FileInputStream datafis = new FileInputStream(ﬁleName);
        BufferedInputStream bufin = new BufferedInputStream(datafis);

        byte[] buffer = new byte[1024];
        int len;
        while (bufin.available() != 0) {
            len = bufin.read(buffer);
            sig.update(buffer, 0, len);
        };

        bufin.close();
        
        boolean verifies = sig.verify(sigToVerify);
        
        return verifies;
    }
    public void saveKeys(String publicKeyFile, String privateKeyFile)
    throws Exception{
        
        byte[] pubKey = this.keyPair.getPublic().getEncoded();
        byte[] privKey = this.keyPair.getPrivate().getEncoded();                
        
        StringWriter publicOutput = new StringWriter();
        PemWriter publicPemWriter = new PemWriter(publicOutput);

        PemObject publicPkPemObject = new PemObject("PUBLIC "+this.keyAlgo+" KEY", pubKey);

        publicPemWriter.writeObject(publicPkPemObject);
        publicPemWriter.close();
        
        FileWriter publicFw = new FileWriter(publicKeyFile);
        publicFw.write(publicOutput.toString());
        publicFw.close();
        
        StringWriter privateOutput = new StringWriter();
        PemWriter privatePemWriter = new PemWriter(privateOutput);

        PemObject privatePkPemObject = new PemObject("PRIVATE "+this.keyAlgo+" KEY", privKey);

        privatePemWriter.writeObject(privatePkPemObject);
        privatePemWriter.close();
        
        FileWriter privateFw = new FileWriter(privateKeyFile);
        privateFw.write(privateOutput.toString());
        privateFw.close();
        
    }
    public void readKeys(String publicKeyFile, String privateKeyFile)
    throws Exception{
        
        int BUFFER_SIZE = 1000;
        
        BufferedReader privatebr = new BufferedReader(new FileReader(privateKeyFile));
        
        privatebr.mark(BUFFER_SIZE);
        
        String line = privatebr.readLine();
        String[] stringArray = line.split(" ");
        
        this.keyAlgo = stringArray[2];
        
        KeyFactory kf = KeyFactory.getInstance(this.keyAlgo);
        
        switch (this.keyAlgo) {
            case "DSA":
                this.signAlgo = "SHA1withDSA";
                break;
            case "RSA":
                this.signAlgo = "SHA1withRSA";
                break;
            default:
                break;
        }
        
        privatebr.reset();
                
        PemReader privateKeyPEMReader = new PemReader(privatebr);
        PemObject privatepo = (PemObject)privateKeyPEMReader.readPemObject();
        PKCS8EncodedKeySpec privatekeysp = new PKCS8EncodedKeySpec(privatepo.getContent()); 
        PrivateKey privatekey = kf.generatePrivate(privatekeysp);
        privatebr.close();
        
        BufferedReader publicbr = new BufferedReader(new FileReader(publicKeyFile));
        
        publicbr.mark(BUFFER_SIZE);
        
        line = publicbr.readLine();
        stringArray = line.split(" ");
        
        if(!this.keyAlgo.equals(stringArray[2])){
             throw new Exception("Different Public key and privte key algo");
        }
        
        publicbr.reset();
        
        PemReader publicKeyPEMReader = new PemReader(publicbr);
        PemObject publicpo = (PemObject)publicKeyPEMReader.readPemObject();
        X509EncodedKeySpec publickeysp = new X509EncodedKeySpec(publicpo.getContent()); 
        PublicKey publickey = kf.generatePublic(publickeysp);
        publicbr.close();
        
        this.keyPair = new KeyPair(publickey,privatekey);
        
    }
    
    private KeyPair keyPair;
    private String keyAlgo;
    private String signAlgo;

}