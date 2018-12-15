package rsa;

import java.math.BigInteger;
import java.util.Random;
import org.junit.Test;

/**
 * @file_name RSA.java
 * @author cantfu
 * @date 2018年4月25日
 * @content TODO
 */
public class RSA {
	/**
	 * 生成两个素数
	 * 若指定的两个素数位数相同，生成的第二个素数是大于等于第一个素数的最小素数
	 * @param bit1 素数1的位数
	 * @param bit2 素数2的位数
	 * @return
	 */
	public BigInteger[] generate_twoPrimes(int bit1,int bit2) {
		Random rnd = new Random();
		BigInteger probablePrime1 = BigInteger.probablePrime(bit1, rnd);
		BigInteger probablePrime2 = BigInteger.probablePrime(bit2, rnd);
		if (probablePrime1.equals(probablePrime2)) {
			probablePrime2 = probablePrime2.nextProbablePrime();
		}
		return new BigInteger[] { probablePrime1, probablePrime2 };
	}

	/**
	 * 使用私钥privateKey对密文c解密
	 * @param c 
	 * @param privateKey
	 * @return
	 */
	public BigInteger decryption(BigInteger c, BigInteger[] privateKey) {
		return exp_mod(c, privateKey[0], privateKey[1]);
	}

	/**
	 * 使用公钥publicKey对明文m加密
	 * <table border="1">
	 * <tr>
	 * 	<th>th1</th>
	 * 	<th>th2</th>
	 * 	<th>th3</th>
	 * </tr>
	 * </table>
	 * @param m
	 * @param publicKey
	 * @return
	 */
	public BigInteger encryption(BigInteger m, BigInteger[] publicKey) {
		return exp_mod(m, publicKey[0], publicKey[1]);
	}
	/**
	 * 指数模运算 （快速指数算法）
	 * @return return exp^exponent (mod n)
	 */
	public BigInteger exp_mod(BigInteger base, BigInteger exponent, BigInteger n) {
		BigInteger result = base;
		int length = exponent.toString(2).length() - 1;// 要比较次数
		// System.out.println("指数二进制长度为:" + (length + 1));

		// 正确:从高位到低位匹配
		while (length-- > 0) {// 判断是否移位完毕
			result = result.multiply(result).mod(n);
			// 该位为1，则flag为false
			boolean flag = exponent.and(BigInteger.valueOf(1L << length)).equals(BigInteger.ZERO);
			// System.out.println(flag);
			if (!flag) {
				result = result.multiply(base).mod(n);
			}
		}
		// 错误：从低位到高位 x
		/*while (exponent.compareTo(BigInteger.ZERO) != 0) {// 判断是否移位完毕
		
			result = result.multiply(result).mod(n);
			// 个位为1 注：1右移多少位都为0
			if (exponent.and(BigInteger.ONE).equals(BigInteger.ONE)) {
				result = result.multiply(base).mod(n);
			}
			exponent = exponent.shiftRight(1);
		}*/
		return result;
	}

	/**
	 * 根据大质数p、q生成公钥、私钥
	 * @param p BigInteger 大质数
	 * @param q BigInteger 大质数
	 * @return BigInteger[][] 公钥、私钥{{e,n},{d,n}}
	 */
	public BigInteger[][] generate_key(BigInteger p, BigInteger q) {
		BigInteger n = p.multiply(q);
		BigInteger fy = p.subtract(BigInteger.ONE)
				.multiply(q.subtract(BigInteger.ONE));
		BigInteger e = new BigInteger("1757316971");// 3889
		System.out.println("私钥为：{" + e + ", " + n + "}");

		BigInteger d = ext_gcd(e, fy)[1];
		while (d.compareTo(BigInteger.ZERO) < 0) {
			d.add(fy);
		}
		System.out.println("公钥为：{" + d + ", " + n + "}");
		return new BigInteger[][] { { e, n }, { d, n } };
	}


	/**
	 * 最大公约数  Euclid算法
	 * @param a
	 * @param b
	 * @return gcd(a,b)
	 */
	public BigInteger gcd(BigInteger a, BigInteger b) {
		if (b.equals(BigInteger.ZERO))
			return a;
		return gcd(b, a.mod(b));
	}

	/**
	 * 扩展欧几里得算法：
	 * 求ax + by = 1中的x与y的整数解（a，b互质）即求a关于b的逆元，ax = 1 (mod b)
	 * @param a
	 * @param b
	 * @return
	 */
	public BigInteger[] ext_gcd(BigInteger a, BigInteger b) {
		if (b.equals(BigInteger.ZERO)) {
			BigInteger x1 = BigInteger.ONE;
			BigInteger y1 = BigInteger.ZERO;
			BigInteger x = x1;
			BigInteger y = y1;
			BigInteger r = a;
			BigInteger[] result = { r, x, y };
			return result;
		} else {
			BigInteger[] temp = ext_gcd(b, a.mod(b));
			BigInteger r = temp[0];
			BigInteger x1 = temp[1];
			BigInteger y1 = temp[2];

			BigInteger x = y1;
			BigInteger y = x1.subtract(a.divide(b).multiply(y1));
			BigInteger[] result = { r, x, y };
			return result;
		}
	}
	@Test
	public void test() {

		// BigInteger p = new BigInteger("71593");
		// BigInteger q = new BigInteger("77041");
		// BigInteger[] twoPrimes = { p, q };

		// 测试随机生成素数
		BigInteger[] twoPrimes = generate_twoPrimes(252, 525);
		System.out.println(twoPrimes[0]);
		System.out.println(twoPrimes[1]);
		// 测试加密
		BigInteger m = new BigInteger("1612050119");
		BigInteger[][] key = generate_key(twoPrimes[0], twoPrimes[1]);
		BigInteger[] publicKey = key[0];
		BigInteger c = encryption(m, publicKey);
		System.out.println("加密密文为:" + c);
		// 测试解密
		BigInteger[] privateKey = key[1];
		BigInteger m1 = decryption(c, privateKey);
		System.out.println("解密后明文为:" + m1);

		// 测试快速指数算法
		/*BigInteger n = p.multiply(q);
		System.out.println(n);
		System.out.println(exp_mod(m, exponent, n));*/
	}
}
