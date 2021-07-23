
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.*;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
//import org.bouncycastle.asn1.x509.Certificate;

public class EncryptDecrypt {
    public KeyStore ks;
    public EncryptDecrypt(String keystore, String ks_pass)
        throws GeneralSecurityException, IOException {
        initKeyStore(keystore, ks_pass);
    }

    public void initKeyStore(String keystore, String ks_pass)
        throws KeyStoreException {
        ks = KeyStore.getInstance(KeyStore.getDefaultType());

        try {
            ks.load(new FileInputStream(keystore), ks_pass.toCharArray());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }

    public X509Certificate getCertificate(String alias)
        throws KeyStoreException{
        return (X509Certificate) ks.getCertificate(alias);
    }

    public PublicKey getPublicKey(String alias)
        throws GeneralSecurityException,IOException{
        return getCertificate(alias).getPublicKey();
    }

    public Key getPrivateKey(String alias, String pk_pass)
        throws GeneralSecurityException,IOException{
        return ks.getKey(alias, pk_pass.toCharArray());
    }

    public byte[] encrypt(Key key, String message)
        throws GeneralSecurityException{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherData = cipher.doFinal(message.getBytes());
        return cipherData;
    }

    public String decrypt(Key key, byte[] message)
        throws GeneralSecurityException{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] cipherData = cipher.doFinal(message);
        return new String(cipherData);
    }
    public void sign(String src, String dest,
                     Certificate[] chain, PrivateKey pk, String digestAlgorithm, String provider,
                     MakeSignature.CryptoStandard subfilter, String reason, String location)
            throws GeneralSecurityException, IOException, DocumentException {
// Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
// Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig");
// Creating the signature
        ExternalDigest digest = new BouncyCastleDigest();
        ExternalSignature signature =
                new PrivateKeySignature(pk, digestAlgorithm, provider);
        MakeSignature.signDetached(appearance, digest, signature, (java.security.cert.Certificate[]) chain,
                null, null, null, 0, subfilter);
    }

}
