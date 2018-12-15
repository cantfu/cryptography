package rsa;

import java.math.BigInteger;

/**
 * @file_name TestRSA.java
 * @author Handle
 * @date 2018年5月13日 下午9:21:10
 * @content TODO
 */
public class TestRSA {
	public static void main(String[] args) {
		RSA1 rsa1 = new RSA1();
		// BigInteger p = new BigInteger("71593");
		// BigInteger q = new BigInteger("77041");
		// BigInteger[] twoPrimes = { p, q };
		BigInteger[] twoPrimes = rsa1.generate_twoPrimes(200, 200);
		// 测试加密
		BigInteger m = new BigInteger("1612050119");
		BigInteger[][] key = rsa1.generate_key(twoPrimes[0], twoPrimes[1]);
		BigInteger[] publicKey = key[0];
		System.out.println("进行加密……");
		BigInteger c = rsa1.encryption(m, publicKey);
		System.out.println("加密密文为:" + c);
		// 测试解密
		BigInteger[] privateKey = key[1];
		System.out.println("对" + m + "进行解密……");
		BigInteger m1 = rsa1.decryption(c, privateKey);
		System.out.println("解密明文为:" + m1);

	}
}
