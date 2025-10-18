package MSD_DIAS;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

public class Test {

    // SHA-256哈希函数
    public static byte[] H3(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input.getBytes());
    }

    // 加载文件中的配置
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

    public static void main(String[] args) throws NoSuchAlgorithmException {
        // 获取双线性配对
        Pairing bp = PairingFactory.getPairing("a.properties");

        // 定义文件路径
        String dir = "E:" + File.separator + "JAVA_code" + File.separator + "JavaStudy" + File.separator + "src" + File.separator + "MSD_DIAS" + File.separator;
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "msk.properties";

        // 从公钥文件加载公钥pk
        Properties pkProp = loadPropFromFile(pkFileName);
        String pkString = pkProp.getProperty("gsk");
        Element pk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkString)).getImmutable();

        // 从公钥文件加载公钥pk
        Properties gProp = loadPropFromFile(pkFileName);
        String gString = gProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();

        // 从私钥文件加载私钥sk
        Properties skProp = loadPropFromFile(skFileName);
        String skString = skProp.getProperty("sk");
        Element sk = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(skString)).getImmutable();

        // 固定输入用于哈希计算
        String input = "yuhang"+System.currentTimeMillis();  // 不再使用时间戳，保持稳定的输入
        byte[] y = H3(input);
        Element Y = bp.getG1().newElementFromHash(y, 0, y.length);


        // 计算 pl = e(Y^sk, g)
        Element pl = bp.pairing(Y.duplicate().powZn(sk), g);  // Y^sk 与 g 配对
        // 计算 pr = e(Y, pk)
        Element pr = bp.pairing(Y, pk);  // Y 与 pk 配对

        // 输出 pl 和 pr，检查是否相等
        System.out.println("pl: " + pl);
        System.out.println("pr: " + pr);
        System.out.println("pl.equals(pr): " + pl.isEqual(pr));  // 比较 pl 和 pr 是否相等

        Element l=bp.pairing(g.powZn(sk),g);
        Element r=bp.pairing(g,pk);
        System.out.println(l.isEqual(r));

        // 输出 l 和 r，检查是否相等
        System.out.println("l: " + l);
        System.out.println("r: " + r);
        System.out.println("l.equals(r): " + l.isEqual(r));  // 比较 l 和 r 是否相等
    }
}
