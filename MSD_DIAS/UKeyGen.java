package MSD_DIAS;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
public class UKeyGen {

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

    // 系统初始化，生成主密钥和公共参数
    public static void setup(String pairingParametersFileName, String mpkFileName, String mskFileName,String uFileName,String skFileName) throws Exception {
        // 从参数文件加载配对
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        // 生成主密钥 msk
        Element msk = bp.getZr().newRandomElement().getImmutable();
        System.out.println("msk: "+msk);
        Properties mskProp = new Properties();
        mskProp.setProperty("msk", Base64.getEncoder().encodeToString(msk.toBytes()));
        storePropToFile(mskProp, mskFileName);

        //用户秘钥sk
        byte[] ID = "yuhang".getBytes(StandardCharsets.UTF_8);
        Element HID = pairing.getG1().newElementFromHash(ID,0,ID.length);
        Element sk = HID.duplicate().powZn(msk);
        System.out.println("sk: " + sk);
        // 保存主密钥到文件
        Properties skProp = new Properties();
        skProp.setProperty("sk", Base64.getEncoder().encodeToString(sk.toBytes()));
        storePropToFile(skProp, skFileName);

        //生成参数u
        Element u=bp.getG1().newRandomElement().getImmutable();
        Properties uProp = new Properties();
        uProp.setProperty("u",Base64.getEncoder().encodeToString(u.toBytes()));
        storePropToFile(uProp,uFileName);
        System.out.println("u: "+u);


        // 生成公共参数 g 和 gx
        Element g = bp.getG1().newRandomElement().getImmutable();
        System.out.println("g: "+g);
        Element mpk = g.duplicate().powZn(msk).getImmutable();
        System.out.println("mpk: "+mpk);
        // 保存公共参数到文件
        Properties mpkProp = new Properties();
        mpkProp.setProperty("g", Base64.getEncoder().encodeToString(g.toBytes()));
        mpkProp.setProperty("mpk", Base64.getEncoder().encodeToString(mpk.toBytes()));
        storePropToFile(mpkProp, mpkFileName);
    }

    public static void main(String[] args) throws Exception {
        // 初始化配对
        initializePairing(); // 先初始化配对

        // 定义文件路径
        String dir = "E:" + File.separator + "JAVA_code" + File.separator + "JavaStudy" + File.separator + "src" + File.separator + "MSD_DIAS" + File.separator;
        String pairingParametersFileName = "a.properties";
        String mpkFileName = dir + "mpk.properties";
        String mskFileName = dir + "msk.properties";
        String uFileName=dir + "u.properties";
        String skFileName=dir + "sk.properties";

        // 进行系统初始化
        setup(pairingParametersFileName, mpkFileName, mskFileName,uFileName,skFileName);

        System.out.println("setup success！");
    }
}
