
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.cert.Certificate;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;


public class HelloWorld {
    public static final String KEYSTORE = "src/main/resources/ks";
    public static final char[] PASSWORD = "cmic@139".toCharArray();
    public static final String SRC = "src/main/resources/FirstTest.pdf";
    public static final String DEST = "results/chapter2/hello_signed%s.pdf";

    public static void main(String[] args) throws FileNotFoundException {


        DigestBC.showTest("MD5");
        DigestBC.showTest("SHA-1");
        DigestBC.showTest("SHA-224");
        DigestBC.showTest("SHA-256");
        DigestBC.showTest("SHA-384");
        DigestBC.showTest("SHA-512");
        DigestBC.showTest("RIPEMD128");
        DigestBC.showTest("RIPEMD160");
        DigestBC.showTest("RIPEMD256");


        //非对称加解密方法

        try {
            EncryptDecrypt app = new EncryptDecrypt("src/main/resources/ks", "cmic@139");
            Key publicKey = app.getPublicKey("demo");
            Key privateKey = app.getPrivateKey("demo", "cmic@139");
            System.out.println("Let's encrypt 'secret message' with a public key");
            byte[] encrypted = app.encrypt(publicKey, "secret message");
            System.out.println("Encrypted message: "
                    + new BigInteger(1, encrypted).toString(16));
            System.out.println("Let's decrypt it with the corresponding private key");
            String decrypted = app.decrypt(privateKey, encrypted);
            System.out.println(decrypted);
            System.out.println("You can also encrypt the message with a private key");
            encrypted = app.encrypt(privateKey, "secret message");
            System.out.println("Encrypted message: "
                    + new BigInteger(1, encrypted).toString(16));
            System.out.println("Now you need the public key to decrypt it");
            decrypted = app.decrypt(publicKey, encrypted);
            System.out.println(decrypted);
            System.out.println("Now print the private key: ");
            System.out.println(privateKey);
            System.out.println("Now print the publickey key: ");
            System.out.println(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(new FileInputStream(KEYSTORE), PASSWORD);
            String alias = (String) ks.aliases().nextElement();
            PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
            Certificate[] chain = (Certificate[]) ks.getCertificateChain(alias);
            EncryptDecrypt app = new EncryptDecrypt("src/main/resources/ks","cmic@139");
            app.sign(SRC, String.format(DEST, 1), chain, pk, DigestAlgorithms.SHA256,
                    provider.getName(), MakeSignature.CryptoStandard.CMS, "Test 1", "Ghent");
            app.sign(SRC, String.format(DEST, 2), chain, pk, DigestAlgorithms.SHA512,
                    provider.getName(), MakeSignature.CryptoStandard.CMS, "Test 2", "Ghent");
            app.sign(SRC, String.format(DEST, 3), chain, pk, DigestAlgorithms.SHA256,
                    provider.getName(), MakeSignature.CryptoStandard.CADES, "Test 3", "Ghent");
            app.sign(SRC, String.format(DEST, 4), chain, pk, DigestAlgorithms.RIPEMD160,
                    provider.getName(), MakeSignature.CryptoStandard.CADES, "Test 4", "Ghent");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
