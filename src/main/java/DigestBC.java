import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class DigestBC extends DigestDefault{
    public static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
    static {
        Security.addProvider(PROVIDER);
    }

    protected DigestBC(String password, String algorithm) throws GeneralSecurityException {
        super(password, algorithm, PROVIDER.getName());
    }

    public static DigestBC getInstance(String password, String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        try {
            return new DigestBC(password, algorithm);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void showTest(String algorithm) {
        try {
            DigestBC app = getInstance("password", algorithm);
            System.out.println("Digest using " + algorithm + ": "
                    + app.getDigestSize());
            System.out.println("Digest: " + app.getDigestAsHexString());
            System.out.println("Is the password 'password'? "
                    + app.checkPassword("password"));
            System.out.println("Is the password 'secret'? "
                    + app.checkPassword("secret"));
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }
}
