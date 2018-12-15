package des;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

/**
 * 
 * @file_name TestDES.java
 * @date 2018年4月2日
 * @content 实现DES算法对文本文件的加密、解密
 */
public class TestDES2 {
	public static void main(String[] args) {
		String key = "abcddacc";
		String plainTxt = "des_plain.txt";
		String cipherTxt = "des_cipher.txt";
		desTxtEncryption(plainTxt, key, cipherTxt);
		desTxtDecryption(cipherTxt, key, plainTxt);
	}

	/**
	 * 对文本文档cipherTxt进行解密，将结果写入plainTxt中
	 * @param cipherTxt 密文文档路径
	 * @param key 解密密钥
	 * @param plainTxt 明文文本文档路径
	 */
	public static void desTxtDecryption(String cipherTxt, String key,
			String plainTxt) {
		try {
			String cipher = "";
			// 读取密文
			cipher = read(cipherTxt, "utf-8");
			System.out.println("密文为：" + cipher);
			// 输出其码值，看是否一致
			for (char a : cipher.toString().toCharArray()) {
				System.out.print((int) a + " ");
			}

			String plain = DES.decryption(cipher.toString(), key);
			System.out.println("解密后明文为：" + plain);
			write(plainTxt, plain, "utf-8");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	/**
	 * 对文本文档plainTxt进行加密，将结果写入cipherTxt中
	 * @param plainTxt 明文文本文档文件路径
	 * @param key 加密密钥
	 * @param cipherTxt 密文文档文件路径
	 */
	public static void desTxtEncryption(String plainTxt, String key,
			String cipherTxt) {
		try {
			// 读取待加密明文
			String plain = read(plainTxt, "utf-8");
			System.out.println("加密明文为：" + plain);
			// System.out.println(plain.length());
			String cipher = DES.encryption(plain, key);
			System.out.println("加密后密文为：" + cipher);
			// 输出其码值，看是否一致
			for (char a : cipher.toCharArray()) {
				System.out.print((int) a + " ");
			}
			System.out.println();

			write(cipherTxt, cipher, "utf-8");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	public static void write(String path, String content, String encoding) throws IOException {
		// File file = new File(path);
		// file.delete();
		// file.createNewFile();
		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(path), encoding));
		writer.write(content);
		writer.close();
	}

	public static String read(String path, String encoding) throws IOException {
		// File file = new File(path);
		BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(path), encoding));
		StringBuilder content = new StringBuilder();
		String line = null;
		while ((line = reader.readLine()) != null) {
			content.append(line).append("\n");
		}
		reader.close();
		return content.toString();
	}
}
