package bd.gov.bcc;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

import java.io.IOException;
import java.security.KeyStore;
import java.util.List;

public class Main {
    public static void main(String[] args) throws IOException {
        // Load unsigned file and signing certificates from local file.
        DSSDocument toSignDocument = new FileDocument("src/main/resources/test.pdf");
        Pkcs12SignatureToken signingToken = new Pkcs12SignatureToken("src/main/resources/keystore.p12", new KeyStore.PasswordProtection("1207".toCharArray()));

// Exctract first private key from the keystore for signing.
        List<DSSPrivateKeyEntry> keys = signingToken.getKeys();
        DSSPrivateKeyEntry privateKey = null;
        for (DSSPrivateKeyEntry entry : keys) {
            privateKey = entry;
            break;
        }
        CertificateToken signerCert = privateKey.getCertificate();

// Construct data to sign.
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setSigningCertificate(signerCert);

        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        PAdESService service = new PAdESService(commonCertificateVerifier);

        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

        SignatureValue signatureValue = signingToken.sign(dataToSign, DigestAlgorithm.SHA256, privateKey);
        DSSDocument signedFile = service.signDocument(toSignDocument, parameters, signatureValue);

        signedFile.save("test-out.pdf");
    }
}