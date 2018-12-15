package rsa;

import java.math.BigInteger;
import java.util.Random;
import org.junit.Test;

/**
 * @file_name RSA.java
 * @author cantfu
 * @date 2018��4��25��
 * @content TODO
 */
public class RSA {
	/**
	 * ������������
	 * ��ָ������������λ����ͬ�����ɵĵڶ��������Ǵ��ڵ��ڵ�һ����������С����
	 * @param bit1 ����1��λ��
	 * @param bit2 ����2��λ��
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
	 * ʹ��˽ԿprivateKey������c����
	 * @param c 
	 * @param privateKey
	 * @return
	 */
	public BigInteger decryption(BigInteger c, BigInteger[] privateKey) {
		return exp_mod(c, privateKey[0], privateKey[1]);
	}

	/**
	 * ʹ�ù�ԿpublicKey������m����
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
	 * ָ��ģ���� ������ָ���㷨��
	 * @return return exp^exponent (mod n)
	 */
	public BigInteger exp_mod(BigInteger base, BigInteger exponent, BigInteger n) {
		BigInteger result = base;
		int length = exponent.toString(2).length() - 1;// Ҫ�Ƚϴ���
		// System.out.println("ָ�������Ƴ���Ϊ:" + (length + 1));

		// ��ȷ:�Ӹ�λ����λƥ��
		while (length-- > 0) {// �ж��Ƿ���λ���
			result = result.multiply(result).mod(n);
			// ��λΪ1����flagΪfalse
			boolean flag = exponent.and(BigInteger.valueOf(1L << length)).equals(BigInteger.ZERO);
			// System.out.println(flag);
			if (!flag) {
				result = result.multiply(base).mod(n);
			}
		}
		// ���󣺴ӵ�λ����λ x
		/*while (exponent.compareTo(BigInteger.ZERO) != 0) {// �ж��Ƿ���λ���
		
			result = result.multiply(result).mod(n);
			// ��λΪ1 ע��1���ƶ���λ��Ϊ0
			if (exponent.and(BigInteger.ONE).equals(BigInteger.ONE)) {
				result = result.multiply(base).mod(n);
			}
			exponent = exponent.shiftRight(1);
		}*/
		return result;
	}

	/**
	 * ���ݴ�����p��q���ɹ�Կ��˽Կ
	 * @param p BigInteger ������
	 * @param q BigInteger ������
	 * @return BigInteger[][] ��Կ��˽Կ{{e,n},{d,n}}
	 */
	public BigInteger[][] generate_key(BigInteger p, BigInteger q) {
		BigInteger n = p.multiply(q);
		BigInteger fy = p.subtract(BigInteger.ONE)
				.multiply(q.subtract(BigInteger.ONE));
		BigInteger e = new BigInteger("1757316971");// 3889
		System.out.println("˽ԿΪ��{" + e + ", " + n + "}");

		BigInteger d = ext_gcd(e, fy)[1];
		while (d.compareTo(BigInteger.ZERO) < 0) {
			d.add(fy);
		}
		System.out.println("��ԿΪ��{" + d + ", " + n + "}");
		return new BigInteger[][] { { e, n }, { d, n } };
	}


	/**
	 * ���Լ��  Euclid�㷨
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
	 * ��չŷ������㷨��
	 * ��ax + by = 1�е�x��y�������⣨a��b���ʣ�����a����b����Ԫ��ax = 1 (mod b)
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

		// ���������������
		BigInteger[] twoPrimes = generate_twoPrimes(252, 525);
		System.out.println(twoPrimes[0]);
		System.out.println(twoPrimes[1]);
		// ���Լ���
		BigInteger m = new BigInteger("1612050119");
		BigInteger[][] key = generate_key(twoPrimes[0], twoPrimes[1]);
		BigInteger[] publicKey = key[0];
		BigInteger c = encryption(m, publicKey);
		System.out.println("��������Ϊ:" + c);
		// ���Խ���
		BigInteger[] privateKey = key[1];
		BigInteger m1 = decryption(c, privateKey);
		System.out.println("���ܺ�����Ϊ:" + m1);

		// ���Կ���ָ���㷨
		/*BigInteger n = p.multiply(q);
		System.out.println(n);
		System.out.println(exp_mod(m, exponent, n));*/
	}
}
