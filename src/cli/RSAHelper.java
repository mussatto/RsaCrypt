package cli;

/**
 *
 * @author vitormussatto
 */
public class RSAHelper {
    
    private RSATools rsaTools = new RSATools();
    private String privateKeyFile = "/path/to/PrivateKey.xml";
    private String publicKeyFile = "/path/to/PublicKey.xml";

    public String encrypt(String str) throws Exception {
            boolean keySetFlg = rsaTools.SetKeyPath(privateKeyFile, publicKeyFile);
            if (!keySetFlg) {
                    throw new Exception ("Problemas ao definir as chaves publicas e privadas para o RSA.");
            }
            return rsaTools.encrypt(str);
    }

    public String decrypt(String str) throws Exception {
            boolean keySetFlg = rsaTools.SetKeyPath(privateKeyFile, publicKeyFile);
            if (!keySetFlg) {
                    throw new Exception ("Problemas ao definir as chaves publicas e privadas para o RSA.");
            }
            return rsaTools.decrypt(str);
    }

    public String getPrivateKeyFile() {
            return privateKeyFile;
    }

    public void setPrivateKeyFile(String privateKeyFile) {
            this.privateKeyFile = privateKeyFile;
    }

    public String getPublicKeyFile() {
            return publicKeyFile;
    }

    public void setPublicKeyFile(String publicKeyFile) {
            this.publicKeyFile = publicKeyFile;
    }

    public RSATools getRsaTools() {
            return rsaTools;
    }

    public void setRsaTools(RSATools rsaTools) {
            this.rsaTools = rsaTools;
    }
    
}
