package des;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * 
 * @file_name TestDES.java
 * @date 2018年4月2日
 * @content 实现DES算法对文本文件的加密、解密
 */
public class TestDES {
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

		FileInputStream in = null;
		FileOutputStream out = null;
		try {
			in = new FileInputStream(cipherTxt);
			out = new FileOutputStream(plainTxt);
			StringBuilder cipher = new StringBuilder();
			byte[] buf = new byte[1024];
			// 开始读取数据
			int len = 0;// 每次读取到的数据的长度
			while ((len = in.read(buf)) != -1) {// len值为-1时，表示没有数据了
				// append方法往sb对象里面添加数据
				cipher.append(new String(buf, 0, len, "utf-8"));
			}

			System.out.println("密文为：" + cipher.toString());
			// 输出其码值，看是否一致
			for (char a : cipher.toString().toCharArray()) {
				System.out.print((int) a + " ");
			}
			System.out.println();
			String plain = DES.decryption(cipher.toString(), key);
			System.out.println("解密后明文为：" + plain);
			out.write(plain.getBytes("utf-8"));
			// out.write(b, off, len);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (in != null)
					in.close();
				if (out != null)
					out.close();
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
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
		FileInputStream in = null;
		FileOutputStream out = null;
		try {
			in = new FileInputStream(new File(plainTxt));
			out = new FileOutputStream(new File(cipherTxt));
			StringBuilder plain = new StringBuilder();
			byte[] buf = new byte[1024];
			// 开始读取数据
			int len = 0;// 每次读取到的数据的长度
			while ((len = in.read(buf)) != -1) {// len值为-1时，表示没有数据了
				// append方法往sb对象里面添加数据
				plain.append(new String(buf, 0, len, "utf-8"));
			}
			System.out.println("加密明文为：" + plain.toString());
			// System.out.println(plain.length());
			String cipher = DES.encryption(plain.toString(), key);
			System.out.println("加密后密文为：" + cipher);
			// 输出其码值，看是否一致
			for (char a : cipher.toCharArray()) {
				System.out.print((int) a + " ");
			}
			System.out.println();

			out.write(cipher.getBytes("utf-8"));
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (in != null)
					in.close();
				if (out != null)
					out.close();
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
		}
	}
}
