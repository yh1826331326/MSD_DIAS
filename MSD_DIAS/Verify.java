package MSD_DIAS;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Verify {

    private static Pairing pairing;

    // 初始化jPBC
    public static void initializePairing() {
        PairingParameters pairingParameters = PairingFactory.getPairingParameters("a.properties");
        pairing = PairingFactory.getPairing(pairingParameters);
    }

    // 从 properties 文件中读取 List<Integer> a_i
    public static List<Integer> loadIntegersFromProperties(String filePath) throws IOException {
        Properties properties = new Properties();
        List<Integer> a_i = new ArrayList<>();

        // 读取文件
        try (InputStream input = new FileInputStream(filePath)) {
            properties.load(input);
        }

        // 读取 a_i 属性并解析为 List<Integer>
        String a_iString = properties.getProperty("a_i");
        if (a_iString != null && !a_iString.isEmpty()) {
            String[] a_iArray = a_iString.split(",");
            for (String value : a_iArray) {
                a_i.add(Integer.parseInt(value));
            }
        }

        return a_i;
    }

    // 从 properties 文件中读取 List<Element> b_i
    public static List<Element> B_iloadElementsFromProperties(String filePath) throws IOException {
        // 从参数文件加载配对
        Pairing bp = PairingFactory.getPairing("a.properties");
        Properties properties = new Properties();
        List<Element> b_i = new ArrayList<>();

        // 读取文件
        try (InputStream input = new FileInputStream(filePath)) {
            properties.load(input);
        }

        // 读取 b_i 属性并解析为 List<Element>
        String b_iString = properties.getProperty("b_i");
        if (b_iString != null && !b_iString.isEmpty()) {
            String[] b_iArray = b_iString.split("\n");
            for (String elementString : b_iArray) {
                elementString = elementString.trim();  // 去除空格和换行符
                if (!elementString.isEmpty()) {
                    // 使用 Base64 解码
                    byte[] decodedBytes = Base64.getDecoder().decode(elementString);
                    // 将字节数组转换为 Element
                    Element element = bp.getZr().newElementFromBytes(decodedBytes).getImmutable();
                    b_i.add(element);
                }
            }
        }

        return b_i;
    }


    // 从 properties 文件中读取 List<Element> sigmas
    public static List<Element> sigmasloadElementsFromProperties(String filePath) throws IOException {
        // 从参数文件加载配对
        Pairing bp = PairingFactory.getPairing("a.properties");
        Properties properties = new Properties();
        List<Element> sigmas = new ArrayList<>();

        // 读取文件
        try (InputStream input = new FileInputStream(filePath)) {
            properties.load(input);
        }

        // 读取 b_i 属性并解析为 List<Element>
        String sigmasString = properties.getProperty("sigmas");
        if (sigmasString != null && !sigmasString.isEmpty()) {
            String[] sigmasArray = sigmasString.split("\n");
            for (String elementString : sigmasArray) {
                elementString = elementString.trim();  // 去除空格和换行符
                if (!elementString.isEmpty()) {
                    // 使用 Base64 解码
                    byte[] decodedBytes = Base64.getDecoder().decode(elementString);
                    // 将字节数组转换为 Element
                    Element element = bp.getG1().newElementFromBytes(decodedBytes).getImmutable();
                    sigmas.add(element);
                }
            }
        }

        return sigmas;
    }

    // 从 properties 文件中读取 List<byte[]> Y_i
    public static List<Element> loadYiListFromProperties(String filePath) throws IOException {
        // 从参数文件加载配对
        Pairing bp = PairingFactory.getPairing("a.properties");

        Properties properties = new Properties();
        List<Element> Y_i = new ArrayList<>();

        // 读取文件
        try (InputStream input = new FileInputStream(filePath)) {
            properties.load(input);
        }

        // 读取 Y_i 属性并解析为 List<Element>
        String Y_iString = properties.getProperty("Y_i");
        if (Y_iString != null && !Y_iString.isEmpty()) {
            String[] Y_iArray = Y_iString.split(",");
            for (String base64String : Y_iArray) {
                base64String = base64String.trim();  // 去除空格和换行符
                if (!base64String.isEmpty()) {
                    // 使用 Base64 解码
                    byte[] decodedBytes = Base64.getDecoder().decode(base64String);

                    // 使用解码后的字节数组创建 Element 对象（假设属于 G1 群）
                    Element element = bp.getG1().newElementFromBytes(decodedBytes);
                    Y_i.add(element);
                }
            }
        }

        return Y_i;
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

    public static boolean verifyBlock(int[] A_i, List<Element> b_i, List<Element> Y_i, List<Element> sigmas, Element g, Element mpk, int q, Element u, Element Proof) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing("a.properties"); //生成双线性配对要用椭圆曲线参数

        Element SigmaAgg = bp.getG1().newOneElement();
        Element Y_iAgg = bp.getG1().newOneElement(); // 初始化 Y_iAgg，而非使用 duplicate

        Element U=u.duplicate().powZn(Proof);

        // 计算 SigmaAgg = ∏ (sigma[a_i]^b_i)
        for (int i = 0; i < q; i++) {
            Element sigma_i = sigmas.get(A_i[i]);
            Element sigmamid=sigma_i.duplicate().powZn(b_i.get(i));
            SigmaAgg.mul(sigmamid); // 直接更新 SigmaAgg
        }

        Element BiAgg = bp.getZr().newZeroElement();
        for (int i = 0; i < q; i++) {
            BiAgg = BiAgg.duplicate().add(b_i.get(i));
        }


        for (int i = 0; i < q; i++) {
            // 应该简化并确保正确赋值
            Element Y_power = Y_i.get(A_i[i]).duplicate().powZn(b_i.get(i));
            Y_iAgg = Y_iAgg.duplicate().mul(Y_power);
        }

        //用户秘钥sk
        byte[] ID = "yuhang".getBytes(StandardCharsets.UTF_8);
        Element HID = pairing.getG1().newElementFromHash(ID,0,ID.length);

        Element Psi = HID.duplicate().powZn(BiAgg).getImmutable();
        Element pr1 = bp.pairing(Psi, mpk);

        // 计算 pl = e(SigmaAgg, g)
        Element pl = bp.pairing(SigmaAgg, g);
        //e(∏^q_{i=1}sigma_[a_i]^b_i)
        System.out.println("双线性配对左边: " + pl);

        Element pr2 = bp.pairing(Y_iAgg.duplicate().mul(U), g);
        //e((∏^q_{i=1}Y_[a_i]^b_i)·u^{Proof}, pk)
        Element pr = pr1.duplicate().mul(pr2);
        System.out.println("双线性配对右边: " + pr);

        boolean result = pl.isEqual(pr);
        System.out.println("Verification result: " + result );

        return result;
    }


    // 从文件名中提取块索引
    private static int extractBlockIndex(File file) {
        String name = file.getName();
        int start = name.lastIndexOf('_') + 1; // 找到最后一个下划线的位置
        int end = name.lastIndexOf('.');       // 找到点的位置
        String indexStr = name.substring(start, end); // 提取索引部分
        return Integer.parseInt(indexStr); // 转换为整数
    }

    // H_1 哈希函数：模拟数据块的哈希值计算
    public static byte[] H1(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        // 从参数文件加载配对
        Pairing bp = PairingFactory.getPairing("a.properties");

        initializePairing();

        // 定义文件路径
        String dir = "E:" + File.separator + "JAVA_code" + File.separator + "JavaStudy" + File.separator + "src" + File.separator + "MSD_DIAS" + File.separator;
        String a_iFileName = dir + "a_i.properties";
        String b_iFileName = dir + "b_i.properties";
        String chalFileName = dir + "chal.properties";
        String mpkFileName = dir + "mpk.properties";
        String mskFileName = dir + "msk.properties";
        String proofFileName = dir + "proof.properties";
        String sigmasFileName = dir + "sigmas.properties";
        String Y_iFileName = dir + "Y_i.properties";
        String uFileName = dir + "u.properties";
        String skFileName = dir + "sk.properties";

        // 从挑战文件加载并恢复挑战chal={q,q1,q2}
        Properties chalProp = loadPropFromFile(chalFileName);
        String qString = chalProp.getProperty("q");
        byte[] Q = Base64.getDecoder().decode(qString);
        int q = ByteBuffer.wrap(Q).getInt(); // 解码回 int 类型，挑战块数量

        // 从公钥文件加载g
        Properties gProp = loadPropFromFile(mpkFileName);
        String gString = gProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();

        // 从公钥文件加载用户私钥pk
        Properties mpkProp = loadPropFromFile(mpkFileName);
        String  mpkString  = mpkProp.getProperty("mpk");
        Element mpk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(mpkString)).getImmutable();

        //从文件加载u
        Properties uProp = loadPropFromFile(uFileName);
        String uString = uProp.getProperty("u");
        Element u = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(uString)).getImmutable();

        //读取 List<Integer> 从 properties 文件 a_i 传参没问题 Zr
        List<Integer> a_i = loadIntegersFromProperties(a_iFileName);
        int[] A_i=a_i.stream()
                .mapToInt(Integer::intValue)
                .toArray();
        //读取 List<Integer> 从 properties 文件 b_i 传参没问题 G1
        List<Element> b_i = B_iloadElementsFromProperties(b_iFileName);

        //从文件中加载证明proof 传参没问题 Zr
        Properties proofProp=loadPropFromFile(proofFileName);
        String proofString=proofProp.getProperty("Proof");
        Element Proof=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(proofString)).getImmutable();

        //从文件中加载sigmas //传参没问题 G1
        List<Element> sigmas = sigmasloadElementsFromProperties(sigmasFileName);

        //从文件加载Y_i
        List<Element> Y_i=loadYiListFromProperties(Y_iFileName);

        verifyBlock(A_i,b_i,Y_i,sigmas,g,mpk,q,u,Proof);

    }
}
