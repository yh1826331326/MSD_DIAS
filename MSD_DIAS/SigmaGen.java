package MSD_DIAS;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class SigmaGen {

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

    // H_3 哈希函数：模拟计算 U_ID || t || i 的哈希值
    public static byte[] H3(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input.getBytes());
    }

    public static List<Element> calculateAllYi(String U_ID, long t, int n) throws NoSuchAlgorithmException {

        Pairing bp=PairingFactory.getPairing("a.properties");//生成双线性配对要用椭圆曲线参数
        List<Element> yList = new ArrayList<>();

        // 遍历 1 到 n，计算每个 Y_i 并加入 List 中
        for (int i = 0; i <n; i++) {

            // 拼接 U_ID, t 和 i 为字符串
            String input = U_ID + t + i;

            // 调用 H_3 函数计算哈希值
            byte[] yi = H3(input);

            // 将计算得到的 Y_i 转换为 Element 类型，使用 pairing 的 G1 群生成元素
            Element yiElement = bp.getG1().newElementFromHash(yi,0, yi.length);
            // 将计算得到的 Y_i 元素添加到 List 中
            yList.add(yiElement);
        }

        return yList;
    }


    // 计算验证标签σ_i
    public static Element calculateSigma(Element sk,byte[] block, int i,Element u,List<Element> yiList) throws NoSuchAlgorithmException {
        // H_1(c_i)
        byte[] T_i = H1(block);
        Element h1_c_i = pairing.getZr().newElementFromHash(T_i, 0, T_i.length);

        // u^{H_3(c_i)}，这里假设 u 是配对群G1的生成元素
       // Element u = pairing.getG1().newRandomElement().getImmutable(); // u 是群G1的生成元
        Element uExponent = u.duplicate().powZn(h1_c_i); // u^(H3(c_i))
        Element Y=yiList.get(i).duplicate().mul(uExponent);
        return Y.duplicate().mul(sk);
    }

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
        Arrays.sort(files, Comparator.comparingInt(SigmaGen::extractBlockIndex));

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

    public static void saveYiListToProperties(List<Element> Y_i, String filePath) throws IOException {
        Properties properties = new Properties();

        // 将 List<Element> 转换为 Base64 编码的字符串
        StringBuilder sb = new StringBuilder();
        for (Element value : Y_i) {
            // 将 Element 转换为字节数组，再进行 Base64 编码
            String base64Value = Base64.getEncoder().encodeToString(value.toBytes());
            sb.append(base64Value).append(",");
        }

        // 移除最后一个逗号
        if (sb.length() > 0) sb.deleteCharAt(sb.length() - 1);

        // 将字符串保存到 properties 文件中
        properties.setProperty("Y_i", sb.toString());

        // 保存到文件
        try (OutputStream output = new FileOutputStream(filePath)) {
            properties.store(output, null);
        }
    }


    // 将 List<Element> 保存到 properties 文件
    public static void saveSigmasToProperties(List<Element> sigmas, String filePath) throws IOException {
        Properties properties = new Properties();

        // 将每个 Element 转换为 Base64 字符串表示
        StringBuilder sb = new StringBuilder();
        for (Element element : sigmas) {
            // 使用 Base64 编码 Element 的字节表示
            String base64String = Base64.getEncoder().encodeToString(element.toBytes());
            sb.append(base64String).append("\n");  // 每个 Element 用换行符分隔
        }

        // 将字符串保存到 properties 文件中
        properties.setProperty("sigmas", sb.toString().trim());

        // 保存到文件
        try (OutputStream output = new FileOutputStream(filePath)) {
            properties.store(output, null);
        }
    }


    public static void main(String[] args) throws Exception {

        // 初始化配对
        initializePairing(); // 先初始化配对
        // 从参数文件加载配对
        Pairing bp = PairingFactory.getPairing("a.properties");

        // 定义文件路径
        String dir = "E:" + File.separator + "JAVA_code" + File.separator + "JavaStudy" + File.separator + "src" + File.separator + "MSD_DIAS" + File.separator;
        String skFileName = dir + "sk.properties";
        String uFileName = dir+"u.properties";
        String sigmasFileName=dir+"sigmas.properties";

        // 用户信息
        String userID = "yuhang"; // 假设的用户ID

        // 从私钥文件加载用户私钥sk
        Properties skProp = loadPropFromFile(skFileName);
        String skString = skProp.getProperty("sk");
        Element sk = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(skString)).getImmutable();

        // 加载u
        Properties uProp = loadPropFromFile(uFileName);
        String uString = uProp.getProperty("u");
        Element u = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(uString)).getImmutable();

        // 读取加密块（假设文件路径为 "encrypted_file.dat"）
        String filePath = "C:\\Users\\22867\\Desktop\\encBlocks";
        List<byte[]> encryptedBlocks = readEncryptedBlocksFromDirectory(filePath);

        //计算Y_i Base64加密过的，用时需解密
        List<Element> Y_i=calculateAllYi(userID,System.currentTimeMillis(),encryptedBlocks.size());
        String Y_iFileName = dir + "Y_i.properties";
        saveYiListToProperties(Y_i,Y_iFileName);

        // 输出Sigma的保存目录
        String outputDirectory = "C:\\Users\\22867\\Desktop\\sigmaOutput"; // 修改为实际输出目录
        Files.createDirectories(Paths.get(outputDirectory)); // 创建输出目录（如果不存在）

        // 用来保存所有的 Sigma
        List<Element> sigmas = new ArrayList<>();

        for (int i = 0; i < encryptedBlocks.size(); i++) {
            byte[] block = encryptedBlocks.get(i);
            Element sigma = calculateSigma(sk, block, i, u,Y_i);
            System.out.println("Sigma for block " + i + ": " + sigma.toString());
            sigmas.add(sigma);
        }
        saveSigmasToProperties(sigmas, sigmasFileName);

    }
}
