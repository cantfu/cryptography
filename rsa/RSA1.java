package rsa;

import java.math.BigInteger;
import java.util.Random;
import org.junit.Test;

/**
 * @file_name RSA1.java
 * @author cantfu
 * @date 2018年4月25日
 * @content TODO
 */
public class RSA1 {
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
		System.out.println("两个素数分别为：");
		System.out.println(probablePrime1);
		System.out.println(probablePrime2);
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
		// 从高位到低位匹配
		while (length-- > 0) {// 判断是否移位完毕
			result = result.multiply(result).mod(n);
			// 该位为1，则flag为false
			boolean flag = exponent.and(BigInteger.ONE.shiftLeft(length)).equals(BigInteger.ZERO);
			// System.out.println(flag);
			if (!flag) {
				result = result.multiply(base).mod(n);
			}
		}
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
		System.out.println("公钥为：{" + e + ", \n" + n + "}");

		BigInteger d = getInverse(e, fy);
		while (d.compareTo(BigInteger.ZERO) < 0) {
			d.add(fy);
		}
		System.out.println("私钥为：{" + d + ", \n" + n + "}");
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

	/**求逆元 d，e*d=1 (mod m)*/
	public BigInteger getInverse(BigInteger e, BigInteger m) {
		System.out.print(e + "的逆元为(mod " + m + "):\n");
		BigInteger x11 = BigInteger.ZERO;
		BigInteger x21 = BigInteger.ONE;
		BigInteger x12 = m;
		BigInteger x22 = e;

		BigInteger temp1;
		BigInteger temp2;
		while (!x22.equals(BigInteger.ONE)) {
			temp1 = x11.subtract(x12.divide(x22).multiply(x21));
			temp2 = x12.mod(x22);

			x11 = x21;
			x21 = temp1;
			x12 = x22;
			x22 = temp2;
		}
		System.out.println(x21);
		return x21.mod(m);
	}
	@Test
	public void testGetInverse() {
		BigInteger b = new BigInteger("1612050119");
		BigInteger e = new BigInteger("1757316971");
		BigInteger m = new BigInteger("5515596313");
		System.out.println(exp_mod(b, e, m));
	}
}
