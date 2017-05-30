//Andrew Tek & Omar Rodriguez
//CS 380-P7
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import java.util.zip.CRC32;
import java.util.zip.Checksum;



public class FileTransfer {
    
    private static Socket soc;
    private static ServerSocket server;
    public static void main(String[] args) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        if (args[0].equals("server") && args[1].equals("private.bin") && args[2].equals("38007")) {
            System.out.println("Mode: Server");
            server(args);
        }
        else if (args[0].equals("client") && args[1].equals("public.bin") && args[2].equals("localhost") && args[3].equals("38007")) {
            System.out.println("Mode: Client");
            File file = new File(args[1]);
            client(file, args);
        }
        else if (args[0].equals("makekeys")) {
            System.out.println("Making Keys");
            makeKeys();
        }
        else
            System.out.println("Invalid input");
    }
    public static void makeKeys() {
        try {
            KeyPairGenerator keys = KeyPairGenerator.getInstance("RSA");
            keys.initialize(4096);
            KeyPair keyPair = keys.genKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("public.bin")))) {
                oos.writeObject(publicKey);
            }
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("private.bin")))) {
                oos.writeObject(privateKey);
            }
        }
        catch (NoSuchAlgorithmException | IOException e)
        {
            e.printStackTrace();
        }
    }
    
    public static void server(String[] args) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        try {
            server = new ServerSocket((Integer.parseInt(args[2])));
            soc = server.accept();
            ObjectInputStream inStream = new ObjectInputStream(soc.getInputStream());
            ObjectOutputStream outStream = new ObjectOutputStream(soc.getOutputStream());
            Object obj;
            StartMessage start;
            StopMessage stop;
            Chunk chunk;
            SecretKeySpec secret = null;
            FileOutputStream foutStream = null;
            int chunkNum = 0;
            while (true) {
                obj = inStream.readObject();
                if (obj.getClass().equals(DisconnectMessage.class)) {
                    soc.close();
                    break;
                }
                else if (obj.getClass().equals(StartMessage.class)) {
                    try{
                        start = (StartMessage) obj;
                        chunkNum = (int) start.getSize() / start.getChunkSize();
                        // Use old file to create new one through substring method
                        
                        String newFile = start.getFile();
                        int dot = newFile.indexOf('.');
                        //System.out.println(newFile);
                        String filename = newFile.substring(0, dot) +"2"+ newFile.substring(dot);
                        foutStream = new FileOutputStream(filename); // opens file if exists
                        Cipher cipher = Cipher.getInstance("RSA");
                        ObjectInputStream fileOut = new ObjectInputStream(new FileInputStream("private.bin"));
                        obj = fileOut.readObject();
                        PrivateKey privKey = (PrivateKey) obj;
                        fileOut.close();
                        //decrypte mode using private key
                        cipher.init(Cipher.DECRYPT_MODE, privKey);
                        byte[] encryptedKey = cipher.doFinal(start.getEncryptedKey());
                        secret = new SecretKeySpec(encryptedKey, "AES");
                        
                        outStream.writeObject(new AckMessage(0));
                    }
                    catch(FileNotFoundException nf)
                    {
                        nf.printStackTrace();
                        outStream.writeObject(new AckMessage(-1));
                    }
                }
                else if(obj.getClass().equals(StopMessage.class)){
                    stop = (StopMessage) obj;
                    soc.shutdownOutput();
                    outStream.writeObject(new AckMessage(-1));
                }
                else if (obj.getClass().equals(Chunk.class)) {
                    AckMessage ack;
                    int countForAcks = 0;
                    while (true) {
                        if (countForAcks != 0) {
                            obj = inStream.readObject();
                        }
                        chunk = (Chunk) obj;
                        if(countForAcks == chunk.getSeq()){
                            Cipher cipher = Cipher.getInstance("AES");
                            cipher.init(Cipher.DECRYPT_MODE, secret);
                            
                            byte[] data = cipher.doFinal(chunk.getData());
                            Checksum checksum = new CRC32();
                            checksum.update(data, 0, data.length);
                            int checksumValue = (int) checksum.getValue();
                            if(checksumValue == chunk.getCrc()) {
                                if(countForAcks < chunkNum){
                                    foutStream.write(data);
                                    foutStream.flush();
                                }
                                else if(countForAcks == chunkNum){
                                    soc.close();
                                    break;
                                }
                                countForAcks++;
                                outStream.writeObject(new AckMessage(countForAcks));
                                System.out.println("Chunk received [" + countForAcks + "/" + chunkNum + "]");
                            }
                            else {
                                outStream.writeObject(new AckMessage(countForAcks));
                            }
                        }
                        else {
                            outStream.writeObject(new AckMessage(countForAcks));
                        }
                    }
                    if (countForAcks == chunkNum) {
                        break;
                    }
                }
                
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
    public static void client(File publicFile, String[] args) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        try {
            
            soc = new Socket(args[2], Integer.parseInt(args[3]));
            
            ObjectOutputStream oos = new ObjectOutputStream(soc.getOutputStream());
            ObjectInputStream inStream = new ObjectInputStream(soc.getInputStream());
            // get input from file
            ObjectInputStream objIn = new ObjectInputStream(new FileInputStream("public.bin"));
            
            Object obj = objIn.readObject();
            PublicKey pubKey = (PublicKey) obj;
            objIn.close();
            
            System.out.printf("%s Connected%n", soc.getInetAddress().getHostAddress());
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            
            SecretKey secretKey = keyGen.generateKey();
            byte[] secretPub = secretKey.getEncoded();
            //read in PUBLIC KEY  from file
            
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            
            // TO SEND encrypted public key int bytes
            byte[] encryptedKey = cipher.doFinal(secretPub);
            //prompt user for path
            System.out.print("Enter path for file: ");
            Scanner sc = new Scanner(System.in);
            String path = sc.nextLine();
            //CHECK if file exists
            File fileOne = new File(path);
            // prompt for umber of chuncks
            System.out.print("Enter chunk size [1024]: ");
            int chunkSize = sc.nextInt();
            //sending startmessage
            StartMessage start = new StartMessage(path, encryptedKey, chunkSize);
            oos.writeObject(start);
            boolean flag = true;
            while(flag){
                
                
                
                obj = inStream.readObject();
                
                AckMessage ack = (AckMessage) obj;
                System.out.println("reaches ack on client");
                // if not stop message
                if (ack.getSeq() != -1) {
                    FileInputStream fileTwo = new FileInputStream(path);
                    int countForAcks = ((int) start.getSize()) / chunkSize;
                    Cipher aCipher = Cipher.getInstance("AES");
                    aCipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    System.out.println("Sending: " + path + ". File size: " + start.getSize() + ".\n");
                    
                    byte[] data;
                    Checksum checksum;
                    int count = 0;
                    
                    while(ack.getSeq() < countForAcks){
                        if (count >= 1) {
                            obj = inStream.readObject();
                            ack = (AckMessage) obj;
                        }
                        if (countForAcks != ack.getSeq()) {
                            data = new byte[chunkSize];
                        }
                        else {
                            int remchunks = ((int) start.getSize()) - (chunkSize * (ack.getSeq()));
                            data = new byte[remchunks];
                        }
                        
                        //checkSum
                        checksum = new CRC32();
                        checksum.update(data, 0, data.length);
                        int checksumValue = (int) checksum.getValue();
                        byte[] chunkData = aCipher.doFinal(data);
                        Chunk chunkArray = new Chunk(ack.getSeq(), chunkData, checksumValue);
                        oos.writeObject(chunkArray);
                        
                        System.out.println("Chunk sent [" + ack.getSeq() + "/" + countForAcks + "]");
                        count++;
                        flag = false;
                    }
                }
            }
        }
        catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }
}
