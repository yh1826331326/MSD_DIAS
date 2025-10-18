package MSD_DIAS;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.io.*;
import java.util.Base64;
public class Encrypted {

    // 将文件分块
    public static List<byte[]> splitFile(File file, int blockSize) throws IOException {
        List<byte[]> blocks = new ArrayList<>(); // 存储每个文件块的列表
        try (FileInputStream fis = new FileInputStream(file)) { // 创建文件输入流读取文件
            byte[] buffer = new byte[blockSize]; // 每次读取的字节数
            int bytesRead; // 实际读取的字节数
            while ((bytesRead = fis.read(buffer)) != -1) { // 当文件未读取完时继续读取
                byte[] block = new byte[bytesRead]; // 创建实际大小的块
                System.arraycopy(buffer, 0, block, 0, bytesRead); // 将读取的数据复制到块中
                blocks.add(block); // 将块添加到列表中
            }
        }
        return blocks; // 返回文件块列表
    }

    // 对数据块进行加密（使用AES对称加密）
    public static byte[] encryptBlock(byte[] block, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES"); // 获取AES加密实例
        cipher.init(Cipher.ENCRYPT_MODE, key); // 初始化加密模式和密钥
        return cipher.doFinal(block); // 加密数据块并返回加密后的字节数组
    }

    // 生成从数据块派生的加密密钥
    public static SecretKey deriveKeyFromData(byte[] dataBlock) throws NoSuchAlgorithmException {
        // 获取SHA-256消息摘要实例
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        // 对数据块进行哈希处理，生成256位的摘要，并取前128位作为AES密钥
        byte[] keyBytes = sha256.digest(dataBlock);
        // 返回AES密钥规范
        return new SecretKeySpec(keyBytes, 0, 16, "AES");
    }

    // 保存块到文件
    public static void saveBlockToFile(byte[] block, String filePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) { // 创建文件输出流
            fos.write(block); // 将块写入文件
        }
    }

    //将密钥保存到文件
    public static void saveKeyToFile(SecretKey key, String directory, int blockIndex) throws IOException {
        // 将密钥转换为Base64编码的字符串
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());

        // 构造文件路径，文件名为 block_{index}_key.dat
        String keyFilePath = directory + File.separator + "block_key_" + blockIndex + ".dat";

        // 将密钥保存到文件
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(keyFilePath))) {
            writer.write(encodedKey);
        }
    }

    public static void main(String[] args) {
        try{
            File file = new File("C:\\Users\\22867\\Desktop\\System Model.pdf"); // 文件路径
            int blockSize = 4048; // 定义块大小

            // 指定输出文件夹路径
            String encryptedBlocksDir = "C:\\Users\\22867\\Desktop\\encBlocks";
            String keysDirectory="C:\\Users\\22867\\Desktop\\keys";

            // 创建输出文件夹并检查是否创建成功
            File encryptedDir = new File(encryptedBlocksDir);
            File keysDir = new File(keysDirectory);

            if (!encryptedDir.exists() && !encryptedDir.mkdirs()) {
                System.err.println("Failed to create directory: " + encryptedBlocksDir);
                return;
            }
            if (!keysDir.exists() && !keysDir.mkdirs()) {
                System.err.println("Failed to create directory: " + keysDirectory);
                return;
            }

            // 将文件分块
            List<byte[]> blocks = splitFile(file, blockSize); // 分割文件为块
            List<byte[]> encryptedBlocks = new ArrayList<>(); // 存储加密块的列表

            // 对每个块进行加密
            for (int i = 0; i < blocks.size(); i++) {
                byte[] block = blocks.get(i); // 获取当前块
                SecretKey key=deriveKeyFromData(block);//生成当前块的密钥
                saveKeyToFile(key,keysDirectory,i);      //保存密钥

                byte[] encryptedBlock = encryptBlock(block, key); // 加密当前块
                encryptedBlocks.add(encryptedBlock); // 将加密块添加到列表

                // 保存加密块到文件
                String encryptedBlockFilePath = encryptedBlocksDir + File.separator + "encrypted_block_" + i + ".dat";
                saveBlockToFile(encryptedBlock, encryptedBlockFilePath); // 保存加密块
            }

        }catch (Exception e) {
            e.printStackTrace(); // 打印异常堆栈信息
        }
    }
}
