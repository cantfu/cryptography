package des;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * 
 * @file_name TestDES.java
 * @date 2018��4��2��
 * @content ʵ��DES�㷨���ı��ļ��ļ��ܡ�����
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
	 * ���ı��ĵ�cipherTxt���н��ܣ������д��plainTxt��
	 * @param cipherTxt �����ĵ�·��
	 * @param key ������Կ
	 * @param plainTxt �����ı��ĵ�·��
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
			// ��ʼ��ȡ����
			int len = 0;// ÿ�ζ�ȡ�������ݵĳ���
			while ((len = in.read(buf)) != -1) {// lenֵΪ-1ʱ����ʾû��������
				// append������sb���������������
				cipher.append(new String(buf, 0, len, "utf-8"));
			}

			System.out.println("����Ϊ��" + cipher.toString());
			// �������ֵ�����Ƿ�һ��
			for (char a : cipher.toString().toCharArray()) {
				System.out.print((int) a + " ");
			}
			System.out.println();
			String plain = DES.decryption(cipher.toString(), key);
			System.out.println("���ܺ�����Ϊ��" + plain);
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
	 * ���ı��ĵ�plainTxt���м��ܣ������д��cipherTxt��
	 * @param plainTxt �����ı��ĵ��ļ�·��
	 * @param key ������Կ
	 * @param cipherTxt �����ĵ��ļ�·��
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
			// ��ʼ��ȡ����
			int len = 0;// ÿ�ζ�ȡ�������ݵĳ���
			while ((len = in.read(buf)) != -1) {// lenֵΪ-1ʱ����ʾû��������
				// append������sb���������������
				plain.append(new String(buf, 0, len, "utf-8"));
			}
			System.out.println("��������Ϊ��" + plain.toString());
			// System.out.println(plain.length());
			String cipher = DES.encryption(plain.toString(), key);
			System.out.println("���ܺ�����Ϊ��" + cipher);
			// �������ֵ�����Ƿ�һ��
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
