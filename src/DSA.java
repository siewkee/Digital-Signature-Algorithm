/*
Name: Hung Siew Kee
Student ID: 5986606

parallels@parallels-Parallels-Virtual-Platform:~$ java -versionopenjdk version "11.0.3" 2019-04-16OpenJDK Runtime Environment (build 11.0.3+7-Ubuntu-1ubuntu218.04.1)OpenJDK 64-Bit Server VM (build 11.0.3+7-Ubuntu-1ubuntu218.04.1, mixed mode, sharing)
*/

import java.security.*;
import java.util.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.math.*;

public class DSA
{
	static private BigInteger h, Y, g, p, q, k, hash_m, x, s, r, p_sub_one;	
	static private BigInteger v;
	static private String hash_m_str;
	
	public static void main (String [] args) throws NoSuchAlgorithmException 
	{
	
		Scanner console = new Scanner(System.in);
		System.out.print("Enter file name to read: " );
		String fileName = console.nextLine();
		
		// read file for input
		String input = readFile(fileName);
		System.out.println("\n**** Signing file contents ****");
		
		// H(M)
		String hash_m_str = SHA1(input);
		
		int hash_msg_int = 0;
		for (int i = 0; i < hash_m_str.length()-1; i++)
	   	hash_msg_int += Integer.parseInt(Character.toString(hash_m_str.charAt(i)), 16);

		hash_m = BigInteger.valueOf(hash_msg_int);
		
		//Public parameters (q, p, g, Y)
		
		generate_p_q();
		System.out.println("\np: " + p);
		System.out.println("\nq: " + q);
		
		// Generate g
		generate_g();
		
		// Generate public key Y
		generate_Y();
		System.out.println("\nPublic Key: " + Y);
		
		// Signature
		// Generate r
		generate_r();
			
		// Generate s
		generate_s();
		
		// write s and r to text file
		writeFile(s, r);
		System.out.println("\n**** Signature has been recorded ****");
		
		// Verify signature 	
		// Verify v == r
		// Print TRUE else FALSE
		
		System.out.print("\nEnter input file name for verification (file with message): " );
		String fileName_verify = console.nextLine();
		
		System.out.print("Enter signature file name for verification (file with signature): " );
		String fileName_sig = console.nextLine();
		
		System.out.println("\n**** Verifying signature ****");
		boolean verify_sig = verify();
		
		
		if (verify_sig == true)
		{
			System.out.println("\n**** Signature verified ****");
			
			System.out.println("\n**** Verifying input file ****");
			String input_verify = readFile(fileName_verify);
			System.out.println("\nInput_prime: \n" + input_verify);
			
			String hash_m_verify = SHA1(input);
			System.out.println("\nHash_m_prime: " + hash_m_verify);
			System.out.println("Hash_m: " + hash_m_verify);
			
			if (hash_m_str.equals(hash_m_verify))
			{
				System.out.println("\n**** Hash and Hash_prime checked ****");
				System.out.println("**** Verification = True ****");
			}
			else
				System.out.println("**** Verification = False **** \nSignature and Input file rejected!");
		}
		else
			System.out.println("****Verification = False ****\nSignature and Input file rejected!");

	}
			
	public static void generate_p_q()
	{
		// identify exponent of base 6 that will generate 512 or more bit
		// base 6 so that bit length is in multiples of 64
		// prime numbers are approximately 6k + 1 numbers away from each other
		
		Random rand = new Random();
		
		BigInteger six = new BigInteger("6");
		BigInteger mul = new BigInteger("1");
		BigInteger six_mul = six.multiply(mul);
		
		q = BigInteger.probablePrime(160, rand);
		p = six_mul.multiply(q).add(BigInteger.ONE);
		
		boolean check_prime = false;
	
		BigInteger constant = new BigInteger("6");
    	BigInteger k_mul = new BigInteger("1");
    	k_mul = k_mul.multiply(constant);
		q = BigInteger.probablePrime(160, rand);
    	p = k_mul.multiply(q).add(BigInteger.ONE);

    	while(true)
    	{
    		int bit_len_p = p.bitLength();
    		
    		if(bit_len_p >= 512 && bit_len_p % 64 == 0)
    		{
    			if (p.isProbablePrime(1000) == true)
    				break;
    			else
    			{
    				q = q.nextProbablePrime();
    				p = k_mul.multiply(q).add(BigInteger.ONE);
    			}
    		}
    		else if(bit_len_p < 512)
    		{
    			q = q.probablePrime(160, rand);
    			k_mul = k_mul.add(BigInteger.ONE);
    			k_mul = k_mul.multiply(constant);
    			p = k_mul.multiply(q).add(BigInteger.ONE);
    		}
    	}
				
	}
	
	public static void generate_g()
	{
		// select h < p-1 
		p_sub_one = p.subtract(BigInteger.ONE);	
		
		boolean check_g = false;

		while(check_g == false)
		{
			h = new BigInteger("3");
			
			// g = h ^ (p-1)/q mod p 
			BigInteger expo = p_sub_one.divide(q).mod(p);
			g = h.modPow(expo, p);

			// check g > 1
			if (g.compareTo(BigInteger.ONE) == 1)
				check_g = true;
			else
				h = h.add(BigInteger.TEN);		
		}
	}
	
	public static void generate_Y()
	{
		// select x randomly (secret key)
		x = new BigInteger("4567");
		
		// Y = g^x mod p
		Y = g.modPow(x, p);
		
	}
	
	public static void generate_r()
	{
		BigInteger gcd_p = BigInteger.ONE;
		BigInteger gcd_q = BigInteger.ONE;
		SecureRandom rand = new SecureRandom();
		
		boolean check_k = false;
		
		while (check_k == false)
		{
			// select k<q
			int k_int = rand.nextInt();
			k = BigInteger.valueOf(k_int);
			
			if (k.compareTo(BigInteger.ONE) == -1)
				k_int = rand.nextInt();
			else if (k.compareTo(q.subtract(BigInteger.ONE)) == -1)
				check_k = true;
		}
		
			// r = (g^k mod p) mod q
		r = g.modPow(k, p);
		r = r.mod(q);
	}
	
	public static void generate_s()
	{	  
		// (k^-1  (hash_m + x * r)) mod q
		BigInteger k_inverse = k.modInverse(q);
		
		BigInteger hash_m_xr = hash_m.add(x.multiply(r));
		s = k_inverse.multiply(hash_m_xr).mod(q);
	}
	
	public static boolean verify()
	{
		String s_File_str = "1";
		String r_File_str = "1";
		
		File file = new File("sig.txt");
		try(BufferedReader br = new BufferedReader (new FileReader(file));)	
		{
			// read line by line
            s_File_str = br.readLine();
            r_File_str = br.readLine();
     	}
		catch (IOException a) 
		{
			System.err.format("IOException: %s%n", a);
			System.exit(-1);
		}
		
		BigInteger s_File = new BigInteger(s_File_str);
		BigInteger r_File = new BigInteger(r_File_str);
		
		// Generate w
			// s^-1 mod q
		BigInteger w = s_File.modInverse(q);
		
		// Generate u1
			// hash_m * w mod q
		BigInteger u1 = hash_m.multiply(w).mod(q);
		
		// Generate u2
			// r * w mod q
		BigInteger u2 = r_File.multiply(w).mod(q);
			
		// Generate v
			// ((g^u1 * y^u2 mod p) mod q)
		BigInteger g_u1 = g.modPow(u1, p);
		BigInteger Y_u2 = Y.modPow(u2, p);
		BigInteger v = g_u1.multiply(Y_u2).mod(p).mod(q);
		
		if (v.equals(r_File))
			return true;
		else
			return false;
		
	}
	
	public static String readFile(String fileName)
	{
		String sb = "";
		
		File file = new File(fileName);
		try(BufferedReader br = new BufferedReader (new FileReader(file));)	
		{
			// read line by line
            String line;
            while ((line = br.readLine()) != null) {
                sb += line += "\n";
            }
		}
		catch (IOException a) 
		{
			System.err.format("IOException: %s%n", a);
			System.exit(-1);
		}
		
		return sb;
	}
	
	public static String SHA1(String input) throws NoSuchAlgorithmException 
	{
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte[] result = mDigest.digest(input.getBytes());
        
        String sb = "";
        
        for (int i = 0; i < result.length; i++) 
            sb += (Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
        
        
		  return sb;
	}
	
	public static void writeFile(BigInteger s, BigInteger r)
	{
		try (FileWriter writer = new FileWriter("sig.txt");
		BufferedWriter bw = new BufferedWriter(writer)) 
		{
		  		bw.write(s.toString() + "\n");
		  		bw.write(r.toString());
		} 
		catch (IOException e) 
		{
			System.err.format("IOException: %s%n", e);
		}
	}

	
	
}
