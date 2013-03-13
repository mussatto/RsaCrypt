package cli;

import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author vitormussatto
 */
public class criptXml {
    
    public static void main(String [] args){
        try {
                String xml = "<?xml version='1.0' encoding='utf-8'?><ORDERINFORMATION>  <ORDER>    <BRAND_ID>2</BRAND_ID></ORDER></ORDERINFORMATION>";

                RSAHelper rsahelper = new RSAHelper();
                String encripted = rsahelper.encrypt(xml);
                //Do something
            } catch (Exception ex) {
            Logger.getLogger(criptXml.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
}
