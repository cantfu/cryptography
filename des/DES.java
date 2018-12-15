package des;

import java.util.BitSet;

/**
 * @author cantfu
 * @file_name DES.java
 * @date 2018��4��2��
 * @content ʵ��DES�㷨���ı��ļ��ļ��ܡ�����
 */
/**cbc����ģʽ��des�㷨*/
public class DES {
	// 16������Կ
	private static BitSet[] subKeys16 = new BitSet[16];
	// �ж��Ƿ��ѻ�ȡ��Կ
	public static boolean haveKeys = false;
	// �������
	private static int count = 0;
	/* IP�û���*/
	private final static int[] IP = {
			58, 50, 42, 34, 26, 18, 10, 2, 
			60, 52, 44, 36, 28, 20, 12, 4, 
			62, 54, 46, 38, 30, 22, 14, 6, 
			64, 56, 48, 40, 32, 24, 16, 8, 
			57, 49, 41, 33, 25, 17, 9, 1, 
			59, 51, 43, 35, 27, 19, 11, 3, 
			61, 53, 45, 37, 29, 21, 13, 5, 
			63, 55, 47, 39, 31, 23, 15, 7
		};  
	/* IP-1���û���*/
	private final static int[] IP_1 = {
			40, 8, 48, 16, 56, 24, 64, 32, 
			39, 7, 47, 15, 55, 23, 63, 31,  
		    38, 6, 46, 14, 54, 22, 62, 30, 
		    37, 5, 45, 13, 53, 21, 61, 29,  
		    36, 4, 44, 12, 52, 20, 60, 28, 
		    35, 3, 43, 11, 51, 19, 59, 27,  
		    34, 2, 42, 10, 50, 18, 58, 26, 
		    33, 1, 41,  9, 49, 17, 57, 25  
	};
	/* ѡ����չ����E  32bit -> 48bit*/
	private final static int[] E = {
			32,  1,  2,  3,  4,  5,  
			4,  5,  6,  7,  8,  9,  
		     8,  9, 10, 11, 12, 13, 
		     12, 13, 14, 15, 16, 17,  
		    16, 17, 18, 19, 20, 21, 
		    20, 21, 22, 23, 24, 25,  
		    24, 25, 26, 27, 28, 29, 
		    28, 29, 30, 31, 32,  1
	};
	/* �û�����P  32bit -> 32bit*/
	private final static int[] P = {
			16, 7, 20, 21, 
			29, 12, 28, 17, 
			1,  15, 23, 26, 
			5,  18, 31, 10,  
		    2,  8, 24, 14, 
		    32, 27, 3,  9,  
		    19, 13, 30, 6,  
		    22, 11, 4,  25  
	};
	/* ��Կ�����е��û�ѡ��1   64bit -> 56bit*/
	private final static int[] PC_1 = {
			 57, 49, 41, 33, 25, 17,  9,  
			 1, 58, 50, 42, 34, 26, 18,  
			 10,  2, 59, 51, 43, 35, 27, 
			 19, 11,  3, 60, 52, 44, 36,  
			 63, 55, 47, 39, 31, 23, 15,  
			 7, 62, 54, 46, 38, 30, 22,  
			 14,  6, 61, 53, 45, 37, 29, 
			 21, 13,  5, 28, 20, 12,  4 
	};
	/* ��Կ�����е��û�ѡ��2  56bit -> 48bit*/
	private final static int[] PC_2 = {
			14, 17, 11, 24, 1, 5, 
			3, 28, 15,  6, 21, 10,  
		    23, 19, 12,  4, 26,  8, 
		    16,  7, 27, 20, 13,  2,  
		    41, 52, 31, 37, 47, 55, 
		    30, 40, 51, 45, 33, 48,  
		    44, 49, 39, 56, 34, 53, 
		    46, 42, 50, 36, 29, 32 	
	};
	/* ��Կ�����е���ѭ����λλ��*/
	private final static int[] LEFT_CYCLIC_SHIFT = {
			1, 1, 2, 2, 2, 2, 2, 2, 
			1, 2, 2, 2, 2, 2, 2, 1
	};
	/* DES��S�ж���  6bit -> 4bit*/
	private final static int[][][] S_BOX = {
			// S1
			{
				{14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
				{0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
				{4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
				{15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}    
			},
		    // S2
			{  
				{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
				{3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
				{0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
				{13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
			},
		    // S3 
			{
				{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
				{13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
				{13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
				{1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}	      
			},
		    // S4 
			{
				{7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
				{13,  8, 11,  5, 6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
				{10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
				{3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
			},
		    // S5   
			{
				{2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
				{14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
				{4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
				{11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
			},
		    // S6  
			{
				{12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
				{10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
				{9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
					{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
			},
		    // S7 
			{
				{4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
				{13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
				{1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
				{6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
			},
		    // S8 
			{
					{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
					{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
					{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
					{ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6,
							11 }
			}
	};

	/**
	 * ������Կ�Ƿ�Ϊ�ϸ��8λ
	 * @param orginKey ��������Կ
	 */
	private static void checkKey(String orginKey) {
		if (orginKey.length() != 8) {
			System.out.println("��Կ����Ϊ8λ�ַ���!");
			System.exit(-1);
		}
	}
	/**
	 *  ����ַ����Ƿ���8��������
	 * @param checked �������ַ���
	 * @return 8���������������ַ�������ASCII��Ϊ0���ַ����
	 */
	private static String checkLength(String checked) {
		StringBuilder newChecked = new StringBuilder(checked);
		if (checked.length() % 8 != 0) {
			count = 8 - (checked.length() % 8);
			for (int i = 0; i < count; ++i) {
				newChecked.append((char) 0);
			}
		}
		return newChecked.toString();
	}
	/**
	 * Dse�ַ�������
	 * @param cipher ����ܵ�����
	 * @param orginKey ��Կ
	 * @return  �����ַ���
	 */
	public static String decryption(String cipher, String orginKey) {
		if (cipher.length() % 8 != 0) {
			System.out.println("error�� ���ı���Ϊ8λ�������ַ���!");
			System.exit(-1);
		}
		checkKey(orginKey);

		StringBuilder strPlain = new StringBuilder();

		for (int i = 0; i < cipher.length() / 8; ++i) {
			String subCipher = cipher.substring(i * 8, (i + 1) * 8);
			BitSet bitCipher = encryption(stringToBitSet(subCipher),
					stringToBitSet(orginKey));
			strPlain.append(BitSetToString(bitCipher));
		}
		return strPlain.substring(0, cipher.length() - count);
	}
	/**
	* DES ��λ����
	* @param cipher 64 bit����
	* @return 64bit����
	*/
	private static BitSet decryption(BitSet cipher, BitSet orginKey) {
		if (!haveKeys) {
			// ����16����Կ
			createKeys(orginKey);
			haveKeys = !haveKeys;
		}
		BitSet left = new BitSet(32);// ��32λ
		BitSet nextLeft = new BitSet(32);// �µ���32λ����һ�ֵ�R
		BitSet nextRight = new BitSet(32);// �µ���32λ�����f��������
		BitSet right = new BitSet(32);// ��32λ
		BitSet currentcipher = new BitSet(64);// cipher
		// 1.IP�û�
		for (int i = 0; i < 64; ++i) {
			currentcipher.set(i, cipher.get(IP[i] - 1));
		}
		// L0��R0
		for (int i = 0; i < 32; ++i) {
			left.set(i, currentcipher.get(i));
		}
		for (int i = 0; i < 32; ++i) {
			right.set(i, currentcipher.get(i + 32));
		}
		// 2. �ֽṹ
		for (int round = 0; round < 16; ++round) {
			nextLeft = (BitSet) right.clone();// ��Ϊֵ��ֵ
			right = fun(right, subKeys16[15 - round]);
			right.xor(left);
			left = nextLeft;
		}
		// 3. L16��R16�����ϲ�
		for (int i = 0; i < 32; ++i)
			currentcipher.set(i, right.get(i));
		for (int i = 32; i < 64; ++i)
			currentcipher.set(i, left.get(i - 32));
		// 4.IP���û�
		for (int i = 0; i < 64; ++i) {
			cipher.set(i, currentcipher.get(IP_1[i] - 1));
		}
		return cipher;
	}
	/**
	 * DES�ַ�������
	 * @param plain �����ַ���
	 * @param orginKey ��Կ�ַ���
	 * @return strCipher �����ַ���
	 */
	public static String encryption(String plain, String orginKey) {
		checkKey(orginKey);
		plain = checkLength(plain);
		// System.out.println(plain);//�����������ַ���
		StringBuilder strCipher = new StringBuilder();

		for (int i = 0; i < plain.length() / 8; ++i) {
			String subPlain = plain.substring(i * 8, (i + 1) * 8);
			// System.out.println(subPlain);//����8λ�������ַ���
			BitSet bitCipher = encryption(stringToBitSet(subPlain),
					stringToBitSet(orginKey));
			System.out.println("����8λ�ַ������ܺ�����Ϊ��" + BitSetToString(bitCipher));
			strCipher.append(BitSetToString(bitCipher));
		}
		return strCipher.toString();
	}
	/**
	 * DES ��λ����
	 * @param plain 64λ����
	 * @param orginKey 64λ��Կ
	 * @return 64λ����
	 */
	private static BitSet encryption(BitSet plain, BitSet orginKey) {
		if (!haveKeys) {
			// ����16����Կ
			createKeys(orginKey);
			haveKeys = !haveKeys;
		}
		
		BitSet left = new BitSet(32);// ��32λ
		BitSet nextLeft = new BitSet(32);// �µ���32λ����һ�ֵ�R
		BitSet nextRight = new BitSet(32);// �µ���32λ�����f��������
		BitSet right = new BitSet(32);// ��32λ
		BitSet currentPlain = new BitSet(64);// plain
		// 1.IP�û�
		for (int i = 0; i < 64; ++i) {
			currentPlain.set(i,plain.get(IP[i] - 1));
		}
		// L0��R0
		for (int i = 0; i < 32; ++i) {
			left.set(i, currentPlain.get(i));
		}
		for (int i = 0; i < 32; ++i) {
			right.set(i, currentPlain.get(i + 32));
		}
		// 2. �ֽṹ
		for (int round = 0; round < 16; ++round) {
			nextLeft = (BitSet) right.clone();// ��Ϊֵ��ֵ
			right = fun(right, subKeys16[round]);
			right.xor(left);
			left = nextLeft;
		}
		// 3. L16��R16�����ϲ�
		for (int i = 0; i < 32; ++i)
			currentPlain.set(i, right.get(i));
		for (int i = 32; i < 64; ++i)
			currentPlain.set(i, left.get(i - 32));
		// 4.IP���û�
		for (int i = 0; i < 64; ++i) {
			plain.set(i, currentPlain.get(IP_1[i] - 1));
		}
		return plain;
	}
	/**
	 * �ֽṹ��f����
	 * @param R 32λ������R��48λ������Կk
	 * @param k
	 * @return ��󾭹�P�û���32λ���
	 */
	private static BitSet fun(BitSet R, BitSet k) {
		BitSet ER = new BitSet(48);
		// 1. 32bitͨ��E����չ��48bit ER
		for (int i = 0; i < 48; ++i) {
			// ER.set(47 - i, R.get(32 - E[i]));
			ER.set(i, R.get(E[i] - 1));
		}
		// 2. ER������Կ�����������
		ER.xor(k);
		// 3. S�д��� : ER(48bit)->SR(32bit)
		BitSet SR = new BitSet(32);
		int x = 0;// ������4bitΪ��λ���ȵļ���
		for(int i = 0; i < 48; i += 6) {
			// ����
			int row = boolToInt(ER.get(i)) * 2 + boolToInt(ER.get(i + 5));
			// ����
			int col = boolToInt(ER.get(i + 1)) * 1
					+ boolToInt(ER.get(i + 2)) * 2
					+ boolToInt(ER.get(i + 3)) * 4
					+ boolToInt(ER.get(i + 4)) * 8;
			int s_out = S_BOX[i / 6][row][col];
			SR.set(x + 3, (s_out & (1 << 3)) != 0);
			SR.set(x + 2, (s_out & (1 << 2)) != 0);
			SR.set(x + 1, (s_out & (1 << 1)) != 0);
			SR.set(x + 0, (s_out & 1) != 0);
			/*SR.set(x + 3, (s_out / 8) == 1);
			SR.set(x + 2, (s_out % 8 / 4) == 1);
			SR.set(x + 1, (s_out % 4 / 2) == 1);
			SR.set(x + 0, (s_out % 2) == 1);*/
			x += 4;

		}
		// 4. P�û���32 -> 32
		BitSet PR = new BitSet(32);
		for (int i = 0; i < 32; ++i) {
			PR.set(i, SR.get(P[i] - 1));
		}

		return PR;
	}
	// booleanת��Ϊ1��0
	private static int boolToInt(boolean b) {
		return b ? 1 : 0;
	}
	/**
	 * ��Կ�������̵�C��D��ѭ������
	 * ????????????�Ƿ�λ�÷��ˣ�������������������*************
	 * @param k 28λ��Կ
	 * @param shift ����λ��
	 * @return 28λ������Կ
	 */
	private static BitSet left_shift(BitSet k, int shift) {
		BitSet key = new BitSet(28);
		for (int i = 0; i < 28; ++i) {
			// ��������Ϊ����
			if (i - shift < 0)
				key.set(i, k.get(i - shift + 28));
			else
				key.set(i, k.get(i - shift));
		}
		return key;
	}
	/**
	 * ����64λ��Կ����16������Կ
	 * @param orginKey 64bit��ʼ��Կ
	 */
	private static void createKeys(BitSet orginKey) {
		BitSet realKey = new BitSet(56);
		// 1.ȥ����żУ��λ. originKey(64bit)->realKey(56bit)
		for (int i = 0; i < 56; ++i) {
			realKey.set(i, orginKey.get(PC_1[i] - 1));
		}
		// 2.16������Կ
		BitSet C = new BitSet(28);// ��28bit
		BitSet D = new BitSet(28);// ��28bit
		BitSet currentKey = new BitSet(56); // ������Կ
		for (int round = 0; round < 16; ++round) {

			for (int i = 0; i < 28; ++i) {
				if (realKey.get(i)) {
					C.set(i);
				}
			}
			for (int i = 0; i < 28; ++i) {
				if (realKey.get(i + 28)) {
					D.set(i);
				}
			}
			// ѭ����λ
			C = left_shift(C, LEFT_CYCLIC_SHIFT[round]);
			D = left_shift(D, LEFT_CYCLIC_SHIFT[round]);
			// PC_2ѹ���û� :56 -> 48,realKey -> currentKey
			for (int i = 0; i < 28; ++i) {
				realKey.set(i, C.get(i));
			}
			for (int i = 0; i < 28; ++i) {
				realKey.set(i + 28, D.get(i));
			}
			for (int i = 0; i < 48; ++i) {
				currentKey.set(i, realKey.get(PC_2[i] - 1));
			}
			subKeys16[round] = currentKey;
		}

	}
	/**
	 * �ַ���תΪ64λ��bitset
	 * @param str ������ַ������ַ�������Ϊ8��������
	 * @return
	 */
	private static BitSet stringToBitSet(String str) {
		BitSet bt = new BitSet();
		char[] charBt = str.toCharArray();
		try {
			if (charBt.length % 8 != 0)
				throw new Exception("�����ַ�������8λ��");
			for (int i = 0; i < charBt.length; i++) {
				for (int j = 0; j < 8; ++j) {
					bt.set(i * 8 + j, (charBt[i] & (1 << j)) != 0);
				}
			}
			int count = bt.size() - str.length() * 8;// �������
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
		return bt;
	}
	private static String BitSetToString(BitSet bt) {
		// System.out.println(bt.toString());//��8λ�ַ�����bitλ
		char[] c = new char[bt.size() / 8];
		// System.out.println(bt.length());//��֤�Ƿ�Ϊ64
		try {
			if (bt.size() != 64) {
				throw new RuntimeException("ת���ַ���ʱ���� ���벻��64λ������");
			}
			// System.out.println(bt.length());
			for (int i = 0; i < bt.size(); ++i) {
				int index = i >> 3;// ����BitSet ��set()Դ��
				// c[index] = 0;
				// c[index] |= 1 << (i % 8);// ����BitSet ��set()Դ�� :words[]
				c[index] |= boolToInt(bt.get(i)) << (i % 8);// i&7
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
		return new String(c);
	}
}
