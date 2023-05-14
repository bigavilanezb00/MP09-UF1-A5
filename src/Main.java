import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        //Ejercicio 1.1

        System.out.println("--------------------------------------------------");
        System.out.println("1.1.1 - Genera un parell de claus (KeyPair) de 1024bits, i utilitza-les per xifrar i desxifrar\n" +
                "un missatge.");
        System.out.println();

        String mensaje = "Hola soy bryan y este es el ejercicio 1.1.1";
        KeyPair keyPair = UtilitatsXifrar.randomGenerate(1024);

        //cifro el mensaje
        System.out.println("***** MENSAJE ENCRIPTADO *****");
        byte[] cifrar = UtilitatsXifrar.encryptA5(mensaje.getBytes(), keyPair.getPublic());
        String cifrado = new String(cifrar, StandardCharsets.UTF_8);
        System.out.println(cifrado);
        System.out.println();

        //descifro el mensaje
        System.out.println("***** MENSAJE DESCRIFRADO *****");
        byte[] descifrar = UtilitatsXifrar.decryptA5(cifrar, keyPair.getPrivate());
        String descifrado = new String(descifrar, StandardCharsets.UTF_8);
        System.out.println(descifrado);
        System.out.println();

        //Ejercicio 1.2

        System.out.println("--------------------------------------------------");
        System.out.println("1.1.1 - Genera un parell de claus (KeyPair) de 1024bits, i utilitza-les per xifrar i desxifrar\n" +
                "un missatge.");
        System.out.println();

        System.out.println("Introduce un mensaje para cifrar: ");
        String mensaje2 = scanner.nextLine();
        KeyPair keyPair2 = UtilitatsXifrar.randomGenerate(1024);

        //cifro el mensaje
        System.out.println("***** MENSAJE ENCRIPTADO *****");
        byte[] cifrar2 = UtilitatsXifrar.encryptA5(mensaje2.getBytes(), keyPair2.getPublic());
        String cifrado2 = new String(cifrar2, StandardCharsets.UTF_8);
        System.out.println(cifrado2);
        System.out.println();

        //descifro el mensaje
        System.out.println("***** MENSAJE DESCRIFRADO *****");
        byte[] descifrar2 = UtilitatsXifrar.decryptA5(cifrar2, keyPair2.getPrivate());
        String descifrado2 = new String(descifrar2, StandardCharsets.UTF_8);
        System.out.println(descifrado2);
        System.out.println();

        // Ejercicio 1.1.3
        System.out.println("1.1.3 - Fes servir els mètodes getPublic i getPrivate per obtenir les claus i el mètodes\n" +
                "derivats d’aquestes claus i observa quines dades aporten");

        System.out.println();
        System.out.println("***** PUBLIC KEY / PRIVATE KEY *****");
        System.out.println();
        System.out.println(keyPair.getPublic()); //devuelve la informacion de la clave publica
        System.out.println();
        System.out.println(keyPair.getPrivate()); // devuelve informacion de la clave privada

        //Ejercicio 1.2.1
        System.out.println("1.2.1 - Fés la lectura d’un dels keystore que tinguis al teu sistema i extreu-ne la següent\n" +
                "informació");
        System.out.println();

        try {
            KeyStore keyStore = UtilitatsXifrar.loadKeyStore("C:/Users/bryan/.keystore", "usuario");


            System.out.println("Tipus d'emmagatzematge: " + keyStore.getType());

            System.out.println("Mida del magatzem: " + keyStore.size());

            // alias
            Enumeration<String> enumeration = keyStore.aliases();
            while(enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();
                System.out.println("alias name: " + alias);
            }

            System.out.println(keyStore.getCertificate("profe"));

            char[] JavaCharArray = {'u', 's', 'u', 'a', 'r', 'i', 'o'};
            System.out.println("Tipus d'algoritme de la clau mykey: " + keyStore.getKey("mykey", JavaCharArray).getAlgorithm());

            // 1.2.2

            System.out.println("Crea una nova clau simètrica (SecretKey) i desa-la (setEntry) al keystore.\n" +
                    "Tingueu en compte que si deseu (mètode store) amb una altra contrasenya el\n" +
                    "keystore queda modificat.\n" +
                    "Fes un captura de pantalla llistant amb la comanda keytool les claus del keystore\n" +
                    "on has fet la nova entrada.");
            System.out.println();

            SecretKey secretKey = UtilitatsXifrar.passwordKeyGeneration("bryan",256);
            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
            KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(JavaCharArray);
            keyStore.setEntry("bryanA5", skEntry,protectionParameter);
            try (FileOutputStream fom = new FileOutputStream("C:/Users/bryan/.keystore")) {
                keyStore.store(fom, JavaCharArray);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // 1.3
        System.out.println("1.3 - Fes un funció que donat un fitxer amb un certificat (.cer) retorni la seva PublicKey. Usa\n" +
                "aquesta funció i mostra per pantalla les dades de la PublicKey llegida.");
        System.out.println();

        System.out.println("Introduzca ruta: ");
        String rutaFichero = scanner.nextLine();
        System.out.println("Ruta fichero .cer: " + rutaFichero);

        PublicKey publicKey = UtilitatsXifrar.getPublicKey(rutaFichero);
        System.out.println("Algoritmo de la clave publica: " + publicKey.getAlgorithm());
        System.out.println("Formato de la clave privada: " + publicKey.getFormat());
        System.out.println("Encoded de la clave publica: " + publicKey.getEncoded());


        System.out.println();

        // 1.4
        System.out.println("Llegir una clau asimètrica del keystore i extreure’n la PublicKey. Imprimir-la per pantalla.\n" +
                "Podeu crear una funció igual que en el punt 3 fent sobrecàrrega)");
        System.out.println();

        System.out.println("Introduzca ruta KeyStore: ");
        String rutaKeyStore = scanner.nextLine();
        System.out.println("Ruta del KeyStore --> " + rutaKeyStore);
        System.out.println();

        String certificadoAlias = "lamevaclauM9";
        System.out.println("Alias: " + certificadoAlias);
        System.out.println();

        System.out.print("Introduce la contraseña de la KeyStore: ");
        String passwKeyStore = scanner.nextLine();
        System.out.println();

        System.out.print("Introdueix el password de la Clau: ");
        String passClave = scanner.nextLine();
        System.out.println();

        KeyStore keyStore1 = UtilitatsXifrar.loadKeyStore(rutaKeyStore, passwKeyStore);
        PublicKey publicKey2 = UtilitatsXifrar.getPublicKey(certificadoAlias);

        System.out.println("Algoritmo de la clave publica: " + publicKey.getAlgorithm());
        System.out.println("Formato de la clave privada: " + publicKey.getFormat());
        System.out.println("Encoded de la clave publica: " + publicKey.getEncoded());

        System.out.println();

        // 1.5
        System.out.println("Fer un funció que donades unes dades i una PrivateKey retorni la signatura. Usa-la i\n" +
                "mostra la signatura per pantalla. (funció dels apunts 1.3.1)");
        System.out.println();

        String mensajeCifrado3 = "Este es el ejercicio 1.5!";
        byte[] firma = UtilitatsXifrar.signData(mensajeCifrado3.getBytes(), keyPair.getPrivate());

        System.out.println("Firma: " + Arrays.toString(firma));

        System.out.println();

        // 1.6
        System.out.println("Fer una funció que donades unes dades, una signatura i la PublicKey, comprovi la validesa\n" +
                "de la informació. (funció dels apunts 1.3.2");
        System.out.println();

        String mensajeCifrado4 = "Ejercicio 1.6!";

        byte[] firma2 = UtilitatsXifrar.signData(mensajeCifrado3.getBytes(), keyPair.getPrivate());
        System.out.println("Validez de la información: "+UtilitatsXifrar.validateSignature(mensajeCifrado4.getBytes(), firma2, keyPair.getPublic()));
        System.out.println();

        // 2.2
        System.out.println("Genereu un parell de claus (KeyPair) i proveu de xifrar i desxifrar un text amb clau\n" +
                "embolcallada.");

        String mensajeCifrado5 = "Este es el ejercicio 2.2!";
        byte[][] mensajeEncriptado = UtilitatsXifrar.encryptWrappedData(mensajeCifrado5.getBytes(), keyPair.getPublic());

        byte[] mensajeDesencriptado = UtilitatsXifrar.decryptWrappedData(mensajeEncriptado, keyPair.getPrivate());
        String fraseDesencriptada = new String(mensajeDesencriptado, 0, mensajeDesencriptado.length);
        System.out.println(fraseDesencriptada);

        System.out.println();
    }
}