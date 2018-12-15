package des;

import java.util.BitSet;

/**
 * @author cantfu
 * @file_name DES.java
 * @date 2018年4月2日
 * @content 实现DES算法对文本文件的加密、解密
 */
/**cbc工作模式的des算法*/
public class DES {
	// 16轮子密钥
	private static BitSet[] subKeys16 = new BitSet[16];
	// 判断是否已获取密钥
	public static boolean haveKeys = false;
	// 补零个数
	private static int count = 0;
	/* IP置换表*/
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
	/* IP-1逆置换表*/
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
	/* 选择扩展运算E  32bit -> 48bit*/
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
	/* 置换运算P  32bit -> 32bit*/
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
	/* 密钥编排中的置换选择1   64bit -> 56bit*/
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
	/* 密钥编排中的置换选择2  56bit -> 48bit*/
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
	/* 密钥编排中的左循环移位位数*/
	private final static int[] LEFT_CYCLIC_SHIFT = {
			1, 1, 2, 2, 2, 2, 2, 2, 
			1, 2, 2, 2, 2, 2, 2, 1
	};
	/* DES的S盒定义  6bit -> 4bit*/
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
	 * 检验密钥是否为严格的8位
	 * @param orginKey 待检测的密钥
	 */
	private static void checkKey(String orginKey) {
		if (orginKey.length() != 8) {
			System.out.println("密钥必须为8位字符串!");
			System.exit(-1);
		}
	}
	/**
	 *  检查字符串是否是8的整数倍
	 * @param checked 待检查的字符串
	 * @return 8的整数倍个数的字符串，用ASCII码为0的字符填充
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
	 * Dse字符串解密
	 * @param cipher 需解密的密文
	 * @param orginKey 密钥
	 * @return  明文字符串
	 */
	public static String decryption(String cipher, String orginKey) {
		if (cipher.length() % 8 != 0) {
			System.out.println("error： 密文必须为8位整数倍字符串!");
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
	* DES 按位解密
	* @param cipher 64 bit密文
	* @return 64bit明文
	*/
	private static BitSet decryption(BitSet cipher, BitSet orginKey) {
		if (!haveKeys) {
			// 生成16轮密钥
			createKeys(orginKey);
			haveKeys = !haveKeys;
		}
		BitSet left = new BitSet(32);// 左32位
		BitSet nextLeft = new BitSet(32);// 新的左32位，上一轮的R
		BitSet nextRight = new BitSet(32);// 新的右32位，结合f函数产生
		BitSet right = new BitSet(32);// 右32位
		BitSet currentcipher = new BitSet(64);// cipher
		// 1.IP置换
		for (int i = 0; i < 64; ++i) {
			currentcipher.set(i, cipher.get(IP[i] - 1));
		}
		// L0、R0
		for (int i = 0; i < 32; ++i) {
			left.set(i, currentcipher.get(i));
		}
		for (int i = 0; i < 32; ++i) {
			right.set(i, currentcipher.get(i + 32));
		}
		// 2. 轮结构
		for (int round = 0; round < 16; ++round) {
			nextLeft = (BitSet) right.clone();// 须为值赋值
			right = fun(right, subKeys16[15 - round]);
			right.xor(left);
			left = nextLeft;
		}
		// 3. L16、R16交换合并
		for (int i = 0; i < 32; ++i)
			currentcipher.set(i, right.get(i));
		for (int i = 32; i < 64; ++i)
			currentcipher.set(i, left.get(i - 32));
		// 4.IP逆置换
		for (int i = 0; i < 64; ++i) {
			cipher.set(i, currentcipher.get(IP_1[i] - 1));
		}
		return cipher;
	}
	/**
	 * DES字符串加密
	 * @param plain 明文字符串
	 * @param orginKey 密钥字符串
	 * @return strCipher 密文字符串
	 */
	public static String encryption(String plain, String orginKey) {
		checkKey(orginKey);
		plain = checkLength(plain);
		// System.out.println(plain);//补零后的明文字符串
		StringBuilder strCipher = new StringBuilder();

		for (int i = 0; i < plain.length() / 8; ++i) {
			String subPlain = plain.substring(i * 8, (i + 1) * 8);
			// System.out.println(subPlain);//该轮8位加密子字符串
			BitSet bitCipher = encryption(stringToBitSet(subPlain),
					stringToBitSet(orginKey));
			System.out.println("本轮8位字符串加密后密文为：" + BitSetToString(bitCipher));
			strCipher.append(BitSetToString(bitCipher));
		}
		return strCipher.toString();
	}
	/**
	 * DES 按位加密
	 * @param plain 64位明文
	 * @param orginKey 64位密钥
	 * @return 64位密文
	 */
	private static BitSet encryption(BitSet plain, BitSet orginKey) {
		if (!haveKeys) {
			// 生成16轮密钥
			createKeys(orginKey);
			haveKeys = !haveKeys;
		}
		
		BitSet left = new BitSet(32);// 左32位
		BitSet nextLeft = new BitSet(32);// 新的左32位，上一轮的R
		BitSet nextRight = new BitSet(32);// 新的右32位，结合f函数产生
		BitSet right = new BitSet(32);// 右32位
		BitSet currentPlain = new BitSet(64);// plain
		// 1.IP置换
		for (int i = 0; i < 64; ++i) {
			currentPlain.set(i,plain.get(IP[i] - 1));
		}
		// L0、R0
		for (int i = 0; i < 32; ++i) {
			left.set(i, currentPlain.get(i));
		}
		for (int i = 0; i < 32; ++i) {
			right.set(i, currentPlain.get(i + 32));
		}
		// 2. 轮结构
		for (int round = 0; round < 16; ++round) {
			nextLeft = (BitSet) right.clone();// 须为值赋值
			right = fun(right, subKeys16[round]);
			right.xor(left);
			left = nextLeft;
		}
		// 3. L16、R16交换合并
		for (int i = 0; i < 32; ++i)
			currentPlain.set(i, right.get(i));
		for (int i = 32; i < 64; ++i)
			currentPlain.set(i, left.get(i - 32));
		// 4.IP逆置换
		for (int i = 0; i < 64; ++i) {
			plain.set(i, currentPlain.get(IP_1[i] - 1));
		}
		return plain;
	}
	/**
	 * 轮结构的f函数
	 * @param R 32位的数据R，48位的子密钥k
	 * @param k
	 * @return 最后经过P置换的32位输出
	 */
	private static BitSet fun(BitSet R, BitSet k) {
		BitSet ER = new BitSet(48);
		// 1. 32bit通过E表扩展成48bit ER
		for (int i = 0; i < 48; ++i) {
			// ER.set(47 - i, R.get(32 - E[i]));
			ER.set(i, R.get(E[i] - 1));
		}
		// 2. ER与子密钥进行异或运算
		ER.xor(k);
		// 3. S盒代换 : ER(48bit)->SR(32bit)
		BitSet SR = new BitSet(32);
		int x = 0;// 用于以4bit为单位长度的计数
		for(int i = 0; i < 48; i += 6) {
			// 行数
			int row = boolToInt(ER.get(i)) * 2 + boolToInt(ER.get(i + 5));
			// 列数
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
		// 4. P置换，32 -> 32
		BitSet PR = new BitSet(32);
		for (int i = 0; i < 32; ++i) {
			PR.set(i, SR.get(P[i] - 1));
		}

		return PR;
	}
	// boolean转化为1或0
	private static int boolToInt(boolean b) {
		return b ? 1 : 0;
	}
	/**
	 * 密钥产生过程的C、D的循环左移
	 * ????????????是否位置反了？？？？？？？？？？*************
	 * @param k 28位密钥
	 * @param shift 左移位数
	 * @return 28位左移密钥
	 */
	private static BitSet left_shift(BitSet k, int shift) {
		BitSet key = new BitSet(28);
		for (int i = 0; i < 28; ++i) {
			// 左移索引为负数
			if (i - shift < 0)
				key.set(i, k.get(i - shift + 28));
			else
				key.set(i, k.get(i - shift));
		}
		return key;
	}
	/**
	 * 根据64位密钥生成16轮子密钥
	 * @param orginKey 64bit初始密钥
	 */
	private static void createKeys(BitSet orginKey) {
		BitSet realKey = new BitSet(56);
		// 1.去掉奇偶校验位. originKey(64bit)->realKey(56bit)
		for (int i = 0; i < 56; ++i) {
			realKey.set(i, orginKey.get(PC_1[i] - 1));
		}
		// 2.16轮子密钥
		BitSet C = new BitSet(28);// 左28bit
		BitSet D = new BitSet(28);// 右28bit
		BitSet currentKey = new BitSet(56); // 本轮密钥
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
			// 循环移位
			C = left_shift(C, LEFT_CYCLIC_SHIFT[round]);
			D = left_shift(D, LEFT_CYCLIC_SHIFT[round]);
			// PC_2压缩置换 :56 -> 48,realKey -> currentKey
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
	 * 字符串转为64位的bitset
	 * @param str 输入的字符串，字符数必须为8的整数倍
	 * @return
	 */
	private static BitSet stringToBitSet(String str) {
		BitSet bt = new BitSet();
		char[] charBt = str.toCharArray();
		try {
			if (charBt.length % 8 != 0)
				throw new Exception("输入字符串不是8位！");
			for (int i = 0; i < charBt.length; i++) {
				for (int j = 0; j < 8; ++j) {
					bt.set(i * 8 + j, (charBt[i] & (1 << j)) != 0);
				}
			}
			int count = bt.size() - str.length() * 8;// 补零个数
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
		return bt;
	}
	private static String BitSetToString(BitSet bt) {
		// System.out.println(bt.toString());//该8位字符串的bit位
		char[] c = new char[bt.size() / 8];
		// System.out.println(bt.length());//验证是否为64
		try {
			if (bt.size() != 64) {
				throw new RuntimeException("转换字符串时出错： 输入不是64位比特数");
			}
			// System.out.println(bt.length());
			for (int i = 0; i < bt.size(); ++i) {
				int index = i >> 3;// 参照BitSet 的set()源码
				// c[index] = 0;
				// c[index] |= 1 << (i % 8);// 参照BitSet 的set()源码 :words[]
				c[index] |= boolToInt(bt.get(i)) << (i % 8);// i&7
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
		return new String(c);
	}
}
