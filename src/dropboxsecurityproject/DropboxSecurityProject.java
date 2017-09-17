package dropboxsecurityproject;

import java.util.*;
import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Locale;
import com.dropbox.core.*;
import com.dropbox.core.DbxDelta.Entry;

/**
 * This project adds encryption and decryption functionality to Dropbox
 *
 * @author Marina George, Shubham Gupta, Anusooyadevi Annadurai
 */
@SuppressWarnings("unused")
public class DropboxSecurityProject {

    /**
     * Main function *
     */
	static boolean key = false;
	static String privkey = "";
	
    public static void main(String[] args) throws Exception {
        selectOption();

    }

    /**
     * Get the file and check if it exists *
     */
    @SuppressWarnings("resource")
	public static String getFile(String name) {
        Scanner scan = new Scanner(System.in);

        System.out.println("Please enter name of " + name);
        String filename = scan.nextLine();
        System.out.println();

        while (!new File(filename).exists()) {
            System.out.println("Please enter a valid filename: ");
            filename = scan.nextLine();
            System.out.println();
        }

        // Display data entered by the user
        System.out.print("File entered: ");
        System.out.println(filename);
        System.out.println();

        return filename;

    }

    /**
     * Function to encrypt the file using the AES GCM encryption
     */
    @SuppressWarnings("resource")
    public static void encryptFile() throws Exception {

        String filename = getFile("shared file");

        // create name for encrypted file
        String fileExtension = filename.substring(filename.lastIndexOf("."),
                filename.length());
        String encryptedFilename = filename.replace(fileExtension, "")
                + " encrypted" + fileExtension;

        FileInputStream input = new FileInputStream(filename);
        File encryptedfile = new File(encryptedFilename);
        encryptedfile.createNewFile();
        FileOutputStream output = new FileOutputStream(encryptedFilename);

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128, random);
        SecretKey key = keyGen.generateKey();

        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final byte[] nonce = new byte[12];
        random.nextBytes(nonce);
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        CipherOutputStream cipherOutput = new CipherOutputStream(output, cipher);

        byte[] bytes = new byte[1024];
        int num = input.read(bytes);
        while (num >= 0) {
            cipherOutput.write(bytes, 0, num);
            num = input.read(bytes);
        }
        cipherOutput.flush();
        cipherOutput.close();
        output.close();
        output.close();
        
        // Take the hash of the encrypted file.
        MessageDigest md = MessageDigest.getInstance("MD5");
        try (InputStream is = Files.newInputStream(Paths.get(encryptedFilename));
             DigestInputStream dis = new DigestInputStream(is, md)) 
        {
        	  //Create byte array to read data in chunks
            byte[] byteArray = new byte[1024];
            int bytesCount = 0; 
              
            //Read file data and update in message digest
            while ((bytesCount = dis.read(byteArray)) != -1) {
                md.update(byteArray, 0, bytesCount);
            };
        }
        byte[] digest = md.digest();
        
        // Adding nonce, digest to the key
        String secretKeyFile = addNonceToKeyFileTotal(key.getEncoded(), nonce, digest,
                "secret key.txt");
        encryptSecretKey(secretKeyFile);
        System.out.println("File Encrypted Succesfully to : " + encryptedFilename);
        System.out.println();
    }

    /**
     * Function to encrypt the secret key using RSA public key
     */
    public static void encryptSecretKey(String secretKeyFile) throws Exception {
        String PublicKeyFilePath = downloadFile(getFileUrl("public key"));

        FileInputStream secretKeyInput = new FileInputStream(secretKeyFile);
        String fileExtension = secretKeyFile.substring(secretKeyFile.lastIndexOf("."),
        		secretKeyFile.length());
        String encryptedFilename = secretKeyFile.replace(fileExtension, "")
                + " encrypted" + fileExtension;

        // read public key from file
        File file = new File(PublicKeyFilePath);
        byte[] publicKeyBytes = Files.readAllBytes(file.toPath());
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        // encrypt secret key using public key
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.ENCRYPT_MODE, publicKey);

        CipherOutputStream cipherOutput = new CipherOutputStream(
                new FileOutputStream(encryptedFilename), c);
        byte[] bytes = new byte[(int) new File(secretKeyFile).length()];
        int num = secretKeyInput.read(bytes);
        while (num >= 0) {
            cipherOutput.write(bytes, 0, num);
            num = secretKeyInput.read(bytes);
        }

        cipherOutput.flush();
        cipherOutput.close();
        file.deleteOnExit();
        secretKeyInput.close();

        // delete the original unencrypted secret key.
        File del = new File(secretKeyFile);
        del.deleteOnExit();
        System.out.println("Encrypted Secret Key generated Succesfully to : " + encryptedFilename);
        System.out.println();
    }

    /**
     * Function to encrypt the private key using the AES GCM encryption and a
     * password
     */
    public static void encryptPrivateKey() throws Exception {
        String filename = getFile("private key");

        String password = getPassword();

        String fileExtension = filename.substring(filename.lastIndexOf("."),
                filename.length());
        String encryptedFilename = filename.replace(fileExtension, "")
                + " encrypted" + fileExtension;

        FileInputStream input = new FileInputStream(filename);
        File encryptedfile = new File(encryptedFilename);
        encryptedfile.createNewFile();
        FileOutputStream output = new FileOutputStream(encryptedFilename);

        SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
        byte[] keyBytes = password.getBytes();
        SecretKeySpec passwordKey = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final byte[] nonce = new byte[12];
        rand.nextBytes(nonce);

        byte[] privateKeyBytes = new byte[(int) new File(filename).length()];
        int num = input.read(privateKeyBytes);

        String filenonce = writetoFile(privateKeyBytes, nonce,
                encryptedFilename);

        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);

        File privNonceFile = new File(filenonce);
        FileInputStream privNonce = new FileInputStream(privNonceFile);

        cipher.init(Cipher.ENCRYPT_MODE, passwordKey, spec);
        CipherOutputStream cipherOutput = new CipherOutputStream(output, cipher);

        byte[] bytes = new byte[(int) privNonceFile.length()];
        int len = privNonce.read(bytes);

        while (len >= 0) {
            cipherOutput.write(bytes, 0, num);
            len = input.read(bytes);
        }

        cipherOutput.flush();
        cipherOutput.close();
        output.close();
        output.close();

        FileInputStream secretKeyInput = new FileInputStream(encryptedFilename);
        byte[] bytes1 = new byte[(int) new File(encryptedFilename).length()];
        int num1 = secretKeyInput.read(bytes1);

        String secretKeyFile2 = addNonceToKeyFile(bytes1, nonce,
                encryptedFilename);

        secretKeyInput.close();
        privNonce.close();
        input.close();
        System.out.println("Private Key Encrypted Succesfully to : " + secretKeyFile2);
        System.out.println();
    }
    
    public static void sharing() throws Exception {
    	
    	String decryptedPrivateKey = "";
    	if(!key) {
    		String privateKeyFile = downloadFile(getFileUrl("private key"));
    		decryptedPrivateKey = decryptPrivateKey(privateKeyFile);
    	}else {
    		decryptedPrivateKey = privkey;
    	}
         String encryptedSecretKey = downloadFile(getFileUrl("encrypted secret key"));
         String secretKeyFile = decryptSecretKey(decryptedPrivateKey,
                 encryptedSecretKey);
		encryptSecretKey(secretKeyFile);
	}

    /**
     * Main Decryption function *
     */
    public static String decryptFileForOwnUse() throws Exception {
    	
        String filename = downloadFile(getFileUrl("encrypted file"));
        String decryptedPrivateKey = "";
    	if(!key) {
    		String privateKeyFile = downloadFile(getFileUrl("private key"));
    		decryptedPrivateKey = decryptPrivateKey(privateKeyFile);
    	}else {
    		decryptedPrivateKey = privkey;
    	}
        String encryptedSecretKey = downloadFile(getFileUrl("encrypted secret key"));
        String secretKeyFile = decryptSecretKey(decryptedPrivateKey,
                encryptedSecretKey);
        String decryptedFile = decryptFile(secretKeyFile, filename);

        return "Decrypted File is at " + decryptedFile + "\n";
    }

    /**
     * Decrypt the private key using the password *
     */
    public static String decryptPrivateKey(String privateKeyFilename)
            throws Exception {
        String password = getPassword();
        String fileExtension = privateKeyFilename.substring(
                privateKeyFilename.lastIndexOf("."),
                privateKeyFilename.length());
        String decryptedFilename = privateKeyFilename
                .replace(fileExtension, "") + " decrypted" + fileExtension;

        FileOutputStream output = new FileOutputStream(decryptedFilename);
        FileInputStream privateKeyInput = new FileInputStream(
                privateKeyFilename);

        byte[] nonce = new byte[12];
        int nonceLen = privateKeyInput.read(nonce, 0, 12);

        byte[] bytes = new byte[1024];
        int num = privateKeyInput.read(bytes);

        SecretKeySpec passwordKey = new SecretKeySpec(password.getBytes(),
                "AES");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        c.init(Cipher.DECRYPT_MODE, passwordKey, spec);
        CipherOutputStream cipherOutput = new CipherOutputStream(output, c);

        while (num >= 0) {
            cipherOutput.write(bytes, 0, num);
            num = privateKeyInput.read(bytes);
        }

        cipherOutput.flush();
        cipherOutput.close();
        output.close();
        privateKeyInput.close();
        System.out.println("Private Key Decrypted Succesfully!");
        File del = new File(privateKeyFilename);
        del.deleteOnExit();
        key = true;
        privkey = decryptedFilename;
        return decryptedFilename;
    }

    /**
     * Decrypt the secret key using the RSA private key *
     */
    @SuppressWarnings("resource")
    private static String decryptSecretKey(String decPrivKey, String encryptedSecretKey) throws Exception {

        String fileExtension = encryptedSecretKey.substring(
                encryptedSecretKey.lastIndexOf("."),
                encryptedSecretKey.length());
        String decryptedFilename = encryptedSecretKey
                .replace(fileExtension, "") + " decrypted" + fileExtension;

        FileInputStream encSecretFile = new FileInputStream(encryptedSecretKey);
        File decryptedFile = new File(decryptedFilename);
        decryptedFile.createNewFile();
        FileOutputStream decryptedFileOutput = new FileOutputStream(
                decryptedFile);

        File file = new File(decPrivKey);
        byte[] privateKeyBytes = Files.readAllBytes(file.toPath());
        new FileInputStream(file).read(privateKeyBytes);

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.DECRYPT_MODE, privateKey);

        CipherOutputStream cipherOutput = new CipherOutputStream(
                decryptedFileOutput, c);
        byte[] bytes = new byte[1024];
        int num = encSecretFile.read(bytes);
        while (num >= 0) {
            cipherOutput.write(bytes, 0, num);
            num = encSecretFile.read(bytes);
        }

        cipherOutput.close();
        encSecretFile.close();
        file.deleteOnExit();
        File del = new File(encryptedSecretKey);
        del.deleteOnExit();
        System.out.println("Secret Key Decrypted Succesfully!");
        System.out.println();

        return decryptedFilename;

    }

    /**
     * Decrypt the file using the AES secret key *
     */
    private static String decryptFile(String secretKeyFile, String filename)
            throws Exception {

        FileInputStream input = new FileInputStream(secretKeyFile);

        String fileExtension = filename.substring(filename.lastIndexOf("."),
                filename.length());
        String decryptedFilename = filename.replace(fileExtension, "")
                + " decrypted" + fileExtension;
        FileInputStream inputFile = new FileInputStream(filename);

        FileOutputStream output = new FileOutputStream(decryptedFilename);

        byte[] nonce = new byte[12];
        int nonceLen = input.read(nonce, 0, 12);
        byte[] digest = new byte[16];
        int digestlen = input.read(digest);
        
        File file = new File(secretKeyFile);
        int totalLen = (int) file.length();
       // byte[] secretKeyBytes = new byte[totalLen - 12];
        byte[] secretKeyBytes = new byte[totalLen - 28];
        int secretLen = input.read(secretKeyBytes);

        // Take the hash of the encrypted file.
        MessageDigest md = MessageDigest.getInstance("MD5");
        try (InputStream is = Files.newInputStream(Paths.get(filename));
             DigestInputStream dis = new DigestInputStream(is, md)) 
        {
        	  //Create byte array to read data in chunks
            byte[] byteArray = new byte[1024];
            int bytesCount = 0; 
              
            //Read file data and update in message digest
            while ((bytesCount = dis.read(byteArray)) != -1) {
                md.update(byteArray, 0, bytesCount);
            };
        }
        byte[] digestnew = md.digest();
        
        if(!Arrays.equals(digest, digestnew)) {
        	System.out.println("Error ! Encrypted File was modified. Hash does not match.");
        } 
        else {
        
        	SecretKeySpec secretKey = new SecretKeySpec(secretKeyBytes, "AES");
        	Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        	GCMParameterSpec spec = new GCMParameterSpec(128, nonce);

        	cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        	CipherOutputStream cipherOutput = new CipherOutputStream(output, cipher);

        	byte[] bytes = new byte[1024];
        	int num = inputFile.read(bytes);
        	while (num >= 0) {
        		cipherOutput.write(bytes, 0, num);
        		num = inputFile.read(bytes);
        	}
        	cipherOutput.flush();
        	cipherOutput.close();
        	output.close();
        	inputFile.close();
        	input.close();       	
        }
        file.deleteOnExit();
    	File del = new File(filename);
    	del.deleteOnExit();
        return decryptedFilename;
    }

    public static void shareFile() throws Exception {

        encryptFile();
        uploadToCloud();
    }

    @SuppressWarnings("resource")
    public static String getPassword() {

        // read key (Key length must be 16 bytes)
        Scanner scan = new Scanner(System.in);
        System.out.println("Please enter a 16 bytes password");
        String password = scan.nextLine();
        System.out.println();
        while (password.getBytes().length != 16) {
            System.out
                    .println("Password must be 16 bytes long. Please try again.");
            System.out
                    .println("Please enter a password or type 'exit' to exit.");
            password = scan.nextLine();
            if (password.equalsIgnoreCase("exit")) {
                System.exit(0);
            }
            System.out.println();
        }
        return password;
    }

    @SuppressWarnings("resource")
    public static void uploadToCloud() throws IOException, DbxException {

        /*
		 * Dropbox uploading and downloading added Created an App console in
		 * Dropbox to obtain a APP KEY and APP SECRET KEY Must be already logged
		 * in to Dropbox Account Goto the URL indicated and must click "Allow"
		 * The provided Authorization code must be entered to the console to
		 * upload further
         */
        // Get app key and secret from the Dropbox developers website.
        final String APPKEY = "blgcg9tsigfywai";		// This one is authorized for
        // the account "Dataappsec"
        final String APPSECRET = "ctbrmqnf3sxmi12";
        Scanner scan = new Scanner(System.in);
        String fname;
        DbxAppInfo appInfo = new DbxAppInfo(APPKEY, APPSECRET);

        DbxRequestConfig config = new DbxRequestConfig("Dropbox Project",
                Locale.getDefault().toString());
        DbxWebAuthNoRedirect webAuth = new DbxWebAuthNoRedirect(config, appInfo);

        String authorizeUrl = webAuth.start();// Sign-in is needed to the App
        System.out
                .println("Log-in dropbox account and Visit the URL and click Allow : \n"
                        + authorizeUrl);
        System.out.println();
        System.out.println("Enter the authorization code.");
        String code = new BufferedReader(new InputStreamReader(System.in))
                .readLine().trim();

        DbxAuthFinish authFinish = webAuth.finish(code);	// Fails on entering
        // Invalid Auth code
        String accessToken = authFinish.accessToken;

        DbxClient client = new DbxClient(config, accessToken);

        System.out.println("The Linked Account of : "
                + client.getAccountInfo().displayName);
        System.out.println();
        String sharedFile = "";
        boolean more = true;

        do {
            fname = getFile("file to upload");
            File inputFile = new File(fname);
            FileInputStream inputStream = new FileInputStream(inputFile);

            try {
                DbxEntry.File uploadedFile = client.uploadFile("/" + fname,
                        DbxWriteMode.add(), inputFile.length(), inputStream);

                System.out.println("Uploaded the file to : "
                        + fname);
                System.out.println();
                sharedFile = uploadedFile.toString().substring(6, uploadedFile.toString().indexOf("\"", 6));
                System.out.println("Now you can share your file with anyone using the following link: \n"
                        + client.createShareableUrl(sharedFile));
                System.out.println();

            } finally {
                System.out.println("Do you want to upload more files? \nPlease type yes or no.");
                if (!scan.nextLine().equalsIgnoreCase("yes")) {
                    more = false;
                }
                inputStream.close();
            }
        } while (more);
    }

    @SuppressWarnings("resource")
    public static void downloadfromcloud() throws IOException, DbxException {

        final String APPKEY = "blgcg9tsigfywai";	// This one is authorized for
        // the account "Dataappsec"
        final String APPSECRET = "ctbrmqnf3sxmi12";
        Scanner scan = new Scanner(System.in);
        String fname;
        DbxAppInfo appInfo = new DbxAppInfo(APPKEY, APPSECRET);

        DbxRequestConfig config = new DbxRequestConfig("Dropbox Project",
                Locale.getDefault().toString());
        DbxWebAuthNoRedirect webAuth = new DbxWebAuthNoRedirect(config, appInfo);

        String authorizeUrl = webAuth.start();
        System.out
                .println("Log-in dropbox account and Visit the URL and click Allow : "
                        + authorizeUrl);
        System.out.println("Enter the authorization code.");
        String code = new BufferedReader(new InputStreamReader(System.in))
                .readLine().trim();
        DbxAuthFinish authFinish = webAuth.finish(code);	// Fails on entering
        // Invalid Auth code
        String accessToken = authFinish.accessToken;

        DbxClient client = new DbxClient(config, accessToken);

        System.out.println("The Linked Account of : "
                + client.getAccountInfo().displayName);
        System.out.println();
        boolean more = true;
        do {
            System.out.println("Enter the name of the file to download");
            fname = scan.nextLine();
            System.out.println();

            FileOutputStream outputStream = new FileOutputStream(fname);
            try {
                //check if file exists
                DbxEntry.File downloadedFile = client.getFile("/" + fname, null,
                        outputStream);
                if (downloadedFile != null)
                    System.out.println("Metadata: " + downloadedFile.toString());
                else 
                    System.out.println("You have entered the wrong file name!");
                System.out.println();
            } finally {
                System.out.println("Do you want to download more files? \nPlease type yes or no.");
                if (!scan.nextLine().equalsIgnoreCase("yes")) {
                    more = false;
                }
                outputStream.close();
            }
        } while (more);
    }

    public static String addNonceToKeyFileTotal(byte[] key, byte[] nonce, byte[] digest,
            String filename) throws Exception {
        FileOutputStream fileOut = new FileOutputStream(filename);
        fileOut.write(nonce);
        fileOut.write(digest);
        fileOut.write(key);
        fileOut.close();
        return filename;
    }
    
    public static String addNonceToKeyFile(byte[] key, byte[] nonce, 
            String filename) throws Exception {
        FileOutputStream fileOut = new FileOutputStream(filename);
        fileOut.write(nonce);
        fileOut.write(key);
        fileOut.close();
        return filename;
    }

    public static String writetoFile(byte[] key, byte[] nonce,
            String filename) throws Exception {
        FileOutputStream fileOut = new FileOutputStream(filename);
        fileOut.write(key);
        fileOut.close();
        return filename;
    }

    @SuppressWarnings("resource")
    public static String getFileUrl(String fileName) {
        Scanner scan = new Scanner(System.in);
        System.out.println("Please enter URL to download " + fileName + ".");
        System.out
                .println("Note: If it is a dropbox URL, It is important that you change the last '0' in the URL to '1' to skip signup screen and force download");
        String url = scan.nextLine();
        System.out.println();
        return url;
    }

    // code adapted from http://stackoverflow.com/questions/13557630/
    @SuppressWarnings("resource")
    public static String downloadFile(String url) throws Exception {
        Scanner scan = new Scanner(System.in);

        URL download = new URL(url);
        ReadableByteChannel rbc = Channels.newChannel(download.openStream());
        System.out.println("Please enter a filename for the downloaded file : ");
        String filename = scan.nextLine();
        File file = new File(filename);
        FileOutputStream fileOut = new FileOutputStream(file);
        fileOut.getChannel().transferFrom(rbc, 0, 1 << 24);
        fileOut.flush();
        fileOut.close();
        rbc.close();
        return file.getAbsolutePath();
    }

    @SuppressWarnings("resource")
    public static void selectOption() throws Exception {
        Scanner scan = new Scanner(System.in);
        boolean exit = false;
        do {
            System.out
                    .println("Please select an option: \n Select '1' for private key encryption. \n "
                            + "Select '2' for file encryption. \n "
                            + "Select '3' for file decryption. \n Select '4' for sharing/uploading to Dropbox."
                            + "\n Select '5' to download from the cloud."
                            + "\n Select '6' to encrypt File key with different public key" 
                            + "\n Select '7' to exit.");
            String option = scan.nextLine();

            switch (option) {
                case "1":
                    encryptPrivateKey();
                    break;
                case "2":
                    encryptFile();
                    break;
                case "3":
                    System.out.println(decryptFileForOwnUse());
                    break;
                case "4":
                    uploadToCloud();
                    break;
                case "5":
                    downloadfromcloud();
                    break;
                case "6":
                	sharing();
                	break;
                case "7":
                    exit = true;
                    System.out.println("Goodbye !");
                    break;
                default:
                    System.out.println("Please enter a valid selection.");
                    option = scan.nextLine();
            }

        } while (!exit);
    }

	

}
