package MSD_DIAS;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;

public class  Proof {
    private static Pairing pairing;

    // 初始化jPBC
    public static void initializePairing() {
        PairingParameters pairingParameters = PairingFactory.getPairingParameters("a.properties");
        pairing = PairingFactory.getPairing(pairingParameters);
    }

    // H_1 哈希函数：模拟数据块的哈希值计算
    public static byte[] H1(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    }

    //从文件夹顺序提取文件
    // 从指定目录中读取加密数据块文件
    public static List<byte[]> readEncryptedBlocksFromDirectory(String directoryPath) throws IOException {
        List<byte[]> blocks = new ArrayList<>();
        File directory = new File(directoryPath);
        // 获取目录下所有以 .dat 结尾的文件
        File[] files = directory.listFiles((dir, name) -> name.endsWith(".dat"));

        if (files == null) {
            throw new IOException("Invalid directory or no .dat files found");
        }

        // 按文件名中的块索引排序
        Arrays.sort(files, Comparator.comparingInt(Proof::extractBlockIndex));

        // 读取每个文件并将其内容作为数据块
        for (File file : files) {
            byte[] block = Files.readAllBytes(file.toPath());
            blocks.add(block);
        }
        return blocks;
    }

    // 从文件名中提取块索引
    private static int extractBlockIndex(File file) {
        String name = file.getName();
        int start = name.lastIndexOf('_') + 1; // 找到最后一个下划线的位置
        int end = name.lastIndexOf('.');       // 找到点的位置
        String indexStr = name.substring(start, end); // 提取索引部分
        return Integer.parseInt(indexStr); // 转换为整数
    }


    // 从文件加载属性
    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)) {
            prop.load(in);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " load failed");
            throw new RuntimeException("Failed to load properties from file: " + fileName, e);
        }
        return prop;
    }

    //计算文件夹中.dat个数
    public static int countDatFilesInDirectory(String directoryPath) {
        // 创建一个File对象表示指定目录
        File directory = new File(directoryPath);

        // 获取目录下所有的文件和文件夹
        File[] files = directory.listFiles();

        // 检查目录是否有效，以及是否包含文件
        if (files == null) {
            throw new IllegalArgumentException("Invalid directory path or directory is empty.");
        }

        int count = 0;

        // 遍历所有文件并检查是否以 ".dat" 结尾
        for (File file : files) {
            // 如果是文件并且扩展名是 ".dat"
            if (file.isFile() && file.getName().endsWith(".dat")) {
                count++;
            }
        }

        // 返回符合条件的文件数量
        return count;
    }


    //伪随机和伪排列的实现
    // 生成一个伪排列（π_1），确保a_i在[1, n]范围内且不重复，用于a_i的生成
    public static List<Integer> calculateAValues(int q, int n, String blockHash, String cspId, long timestamp,Element q1) throws NoSuchAlgorithmException {
        List<Integer> aValues = new ArrayList<>();
        Set<Integer> uniqueValues = new HashSet<>(); // 用于确保a_i值不重复

        // SHA-256 Hash算法实例
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // 遍历挑战块的数量
        for (int i = 0; i < q; i++) {
            // 拼接输入数据: H_{block} || CSP_{ID} || t || q_1 || i
            String input = blockHash + cspId + timestamp + q1.toString() + i;

            // 计算哈希值
            byte[] hashBytes = md.digest(input.getBytes());

            // 将哈希值转换为一个数字（伪随机数）
            long hashValue = bytesToLong(hashBytes);

            // 映射到1到n的范围，并确保唯一性
            int mappedValue = (int) (Math.abs(hashValue % n) );

            // 确保a_i唯一
            while (uniqueValues.contains(mappedValue)) {
                // 如果已存在该值，重新生成一个映射
                hashValue = (hashValue + 1) % n;
                mappedValue = (int) (Math.abs(hashValue % n) );
            }

            // 添加到结果集合中
            aValues.add(mappedValue);
            uniqueValues.add(mappedValue);

        }

        return aValues;
    }
    // 计算b_i值
    public static List<Element> calculateBValues(int q, String blockHash, String cspId, long timestamp, Element q2) throws NoSuchAlgorithmException {

        List<Element> bValues = new ArrayList<>();
        Pairing bp=PairingFactory.getPairing("a.properties");//生成双线性配对要用椭圆曲线参数
        Field Zr=bp.getZr();//生成整数群

        // SHA-256 Hash算法实例
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // 遍历挑战块的数量
        for (int i = 1; i <= q; i++) {
            // 拼接输入数据: H_{block} || CSP_{ID} || t || q_2 || i
            String input = blockHash + cspId + timestamp + q2.toString() + (i-1);  // 假设 Element q2 有 toString 方法

            // 计算哈希值
            byte[] hashBytes = md.digest(input.getBytes());

            Element h=Zr.newElementFromHash(hashBytes,0, hashBytes.length);

            // 添加到 bValues 列表
            bValues.add(h);
        }
        return bValues;
    }
    // 将字节数组转换为long型数字（用于伪随机数生成）,用于a_i生成
    private static long bytesToLong(byte[] bytes) {
        long value = 0;
        for (int i = 0; i < Math.min(bytes.length, 8); i++) {
            value |= ((long) (bytes[i] & 0xff)) << (8 * (7 - i));
        }
        return value;
    }
    // 计算 p_i = b_i * H_3(c_{a_i})
    public static List<Element> calculateP(List<Integer> a_i, List<Element> b_i, List<byte[]> encryptedBlocks) throws NoSuchAlgorithmException {
        List<Element> p_i = new ArrayList<>();
        Pairing bp=PairingFactory.getPairing("a.properties");//生成双线性配对要用椭圆曲线参数
        Field Zr=bp.getZr();//生成整数群

        for (int i = 0; i < a_i.size(); i++) {
            int index = a_i.get(i);
            Element b = b_i.get(i);
            byte[] encryptedBlock = encryptedBlocks.get(index);

            // 计算 H_3(c_{a_i})
            byte[] h3Value = H1(encryptedBlock);
            Element h=Zr.newElementFromHash(h3Value,0, h3Value.length);
            // 计算 p_i = b_i * H_3(c_{a_i})
            Element p = b.duplicate().mul(h);
            p_i.add(p);
        }

        return p_i;
    }

    // 计算所有权证明 Proof_PoW = sum(p_i)
    public static Element calculateProofPoW(List<Element> p_i) {
        Pairing bp=PairingFactory.getPairing("a.properties");//生成双线性配对要用椭圆曲线参数
        Field Zr=bp.getZr();//生成整数群

        Element proofPoW=Zr.newZeroElement();
        long time=System.currentTimeMillis();
        for (Element p : p_i) {
            proofPoW = proofPoW.duplicate().add(p);
        }

        System.out.println("Time cost "+(System.currentTimeMillis()-time)+"ms");
        return proofPoW;
    }

    // 将属性保存到文件
    public static void storePropToFile(Properties prop, String fileName) {
        try (FileOutputStream out = new FileOutputStream(fileName)) {
            prop.store(out, null);
        } catch (IOException e) {
            e.printStackTrace();//打印异常的堆栈跟踪信息，帮助调试。
            System.out.println(fileName + " save failed");
            throw new RuntimeException("Failed to save properties to file: " + fileName, e);
        }
    }

    // 将 List<Integer> 保存到 properties 文件
    public static void saveIntegersToProperties(List<Integer> a_i, String filePath) throws IOException {
        Properties properties = new Properties();

        // 将 List<Integer> 转换为逗号分隔的字符串
        StringBuilder sb = new StringBuilder();
        for (Integer value : a_i) {
            sb.append(value).append(",");
        }
        // 移除最后一个逗号
        if (sb.length() > 0) sb.deleteCharAt(sb.length() - 1);

        // 将字符串保存到 properties 文件中
        properties.setProperty("a_i", sb.toString());

        // 保存到文件
        try (OutputStream output = new FileOutputStream(filePath)) {
            properties.store(output, null);
        }
    }

    // 将 List<Element> 保存到 properties 文件
    public static void saveElementsToProperties(List<Element> b_i, String filePath) throws IOException {
        Properties properties = new Properties();

        // 将每个 Element 转换为 Base64 字符串表示
        StringBuilder sb = new StringBuilder();
        for (Element element : b_i) {
            // 使用 Base64 编码 Element 的字节表示
            String base64String = Base64.getEncoder().encodeToString(element.toBytes());
            sb.append(base64String).append("\n");  // 每个 Element 用换行符分隔
        }

        // 将字符串保存到 properties 文件中
        properties.setProperty("b_i", sb.toString().trim());

        // 保存到文件
        try (OutputStream output = new FileOutputStream(filePath)) {
            properties.store(output, null);
        }
    }




    public static void main(String[] args) {
        try{
            //配对初始化
            initializePairing();

            long timestamp = System.currentTimeMillis();
            // 读取加密块
            String filePath = "C:\\Users\\22867\\Desktop\\encBlocks";
            List<byte[]> encryptedBlocks = readEncryptedBlocksFromDirectory(filePath);

            //获取文件夹中数据块的数量
            int n=countDatFilesInDirectory(filePath);//总块数

            // 定义文件路径
            String dir = "E:" + File.separator + "JAVA_code" + File.separator + "JavaStudy" + File.separator + "src" + File.separator + "MSD_DIAS" + File.separator;
            String chalFileName=dir+"chal.properties";

            // 从挑战文件加载并恢复挑战chal={q,q1,q2}
            Properties chalProp = loadPropFromFile(chalFileName);
            String qString = chalProp.getProperty("q");
            String q1String = chalProp.getProperty("q1");
            String q2String = chalProp.getProperty("q2");
            byte[] Q = Base64.getDecoder().decode(qString);
            int q = ByteBuffer.wrap(Q).getInt(); // 解码回 int 类型，挑战块数量
            Element q1 = pairing.getZr().newElementFromBytes(Base64.getDecoder().decode(q1String)).getImmutable();
            Element q2 = pairing.getZr().newElementFromBytes(Base64.getDecoder().decode(q2String)).getImmutable();


            String blockHash = "block_hash_example";
            String cspId = "CSP_ID_example";

            String a_iFileName = dir + "a_i.properties";
            String b_iFileName = dir + "b_i.properties";
            String proofFileName = dir + "proof.properties";

            System.out.print("i:");

            //q个a_i
            List<Integer> a_i = calculateAValues(q, n, blockHash, cspId, timestamp,q1);
            for (Integer value:a_i){
                System.out.print(value+",");
            }

            System.out.println();
            System.out.print("l_i:");
            //q个b_i
            List<Element> b_i = calculateBValues(q, blockHash, cspId, timestamp,q2);
            for (Element value:b_i){
                System.out.print(value+",");
            }
            long time=System.currentTimeMillis();
            //计算p_i
            System.out.println();
            System.out.print("p_i:");
            List<Element> p_i= calculateP(a_i,b_i,encryptedBlocks);
            for (Element value:p_i){
                System.out.print(value+",");
            }
           //聚合p_i计算proof
            Element Proof= calculateProofPoW(p_i);
            System.out.println("聚合证明："+Proof);

            Properties proofProp=new Properties();
            proofProp.setProperty("Proof",Base64.getEncoder().encodeToString(Proof.toBytes()));
            storePropToFile(proofProp, proofFileName);

            System.out.println("Time cost: "+(System.currentTimeMillis()-time)+" ms");
            saveIntegersToProperties(a_i,a_iFileName);
            saveElementsToProperties(b_i,b_iFileName);
        }catch (Exception e) {
            e.printStackTrace(); // 打印异常堆栈信息
        }
    }
}


