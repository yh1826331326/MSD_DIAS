package MSD_DIAS;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;

public class chal {

    private static SecureRandom random = new SecureRandom();
    private static Pairing pairing;

    // 初始化jPBC
    public static void initializePairing() {
        // 加载a.properties文件并创建配对
        PairingParameters pairingParameters = PairingFactory.getPairingParameters("a.properties");
        pairing = PairingFactory.getPairing(pairingParameters);
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

    // 生成一个随机数 q1 和 q2 属于 Z_p，假设 p 是素数
    public static Element generateRandomZp(Element p) {
        return pairing.getZr().newRandomElement().getImmutable();  // 随机生成 0 到 p-1 之间的数
    }

    // 生成所有权挑战 Chal_PoW = (q, q1, q2)
    public static ChalPoW generateChallenge(int q, Element p) {
        // 使用传入的 q 值，而不是随机生成
        Element q1 = generateRandomZp(p);
        Element q2 = generateRandomZp(p);

        return new ChalPoW(q, q1, q2);
    }

    // 所有权挑战类，包含 q, q1, q2
    public static class ChalPoW {
        int q;
        Element q1;
        Element q2;

        public ChalPoW(int q, Element q1, Element q2) {
            this.q = q;
            this.q1 = q1;
            this.q2 = q2;
        }

        @Override
        public String toString() {
            return "Chal_PoW = (q: " + q + ", q1: " + q1 + ", q2: " + q2 + ")";
        }
    }

    // 测试
    public static void main(String[] args) {
        int q = 1;  // 设定一个固定的 q 值
        initializePairing(); // 初始化配对

        // 获取配对的素数 p
        Element p = pairing.getZr().newRandomElement().getImmutable();

        ChalPoW challenge = generateChallenge(q, p);  // 使用指定的 q 值
        System.out.println(challenge);

        // 定义文件路径
        String dir = "E:" + File.separator + "JAVA_code" + File.separator + "JavaStudy" + File.separator + "src" + File.separator + "MSD_DIAS" + File.separator;
        String chal = dir + "chal.properties";


        // 保存公共参数到文件
        Properties chalProp = new Properties();

        // 将 int 转换为字节数组
        byte[] qBytes = ByteBuffer.allocate(4).putInt(challenge.q).array();  // 将 int 转为 4 字节数组
        chalProp.setProperty("q", Base64.getEncoder().encodeToString(qBytes)); // 将 q 转为 Base64 编码

        chalProp.setProperty("q1", Base64.getEncoder().encodeToString(challenge.q1.toBytes()));
        chalProp.setProperty("q2", Base64.getEncoder().encodeToString(challenge.q2.toBytes()));
        storePropToFile(chalProp, chal);
    }

}
