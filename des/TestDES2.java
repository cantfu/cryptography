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
 * @date 2018��4��2��
 * @content ʵ��DES�㷨���ı��ļ��ļ��ܡ�����
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
	 * ���ı��ĵ�cipherTxt���н��ܣ������д��plainTxt��
	 * @param cipherTxt �����ĵ�·��
	 * @param key ������Կ
	 * @param plainTxt �����ı��ĵ�·��
	 */
	public static void desTxtDecryption(String cipherTxt, String key,
			String plainTxt) {
		try {
			String cipher = "";
			// ��ȡ����
			cipher = read(cipherTxt, "utf-8");
			System.out.println("����Ϊ��" + cipher);
			// �������ֵ�����Ƿ�һ��
			for (char a : cipher.toString().toCharArray()) {
				System.out.print((int) a + " ");
			}

			String plain = DES.decryption(cipher.toString(), key);
			System.out.println("���ܺ�����Ϊ��" + plain);
			write(plainTxt, plain, "utf-8");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	/**
	 * ���ı��ĵ�plainTxt���м��ܣ������д��cipherTxt��
	 * @param plainTxt �����ı��ĵ��ļ�·��
	 * @param key ������Կ
	 * @param cipherTxt �����ĵ��ļ�·��
	 */
	public static void desTxtEncryption(String plainTxt, String key,
			String cipherTxt) {
		try {
			// ��ȡ����������
			String plain = read(plainTxt, "utf-8");
			System.out.println("��������Ϊ��" + plain);
			// System.out.println(plain.length());
			String cipher = DES.encryption(plain, key);
			System.out.println("���ܺ�����Ϊ��" + cipher);
			// �������ֵ�����Ƿ�һ��
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
