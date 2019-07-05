package criptografia;

import java.io.FileOutputStream;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import sun.security.tools.keytool.CertAndKeyGen;

import javax.security.auth.x500.X500Principal;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.InputMismatchException;
import java.util.Scanner;

public class programa {

	public static Cipher rsa;
	public static Cipher aes;
	public static Cipher des;

	public static void main(String[] args) throws Exception {

		Scanner sc = new Scanner(System.in);
		boolean salir = false;
		boolean salirRSA = false;
		boolean salirAES = false;
		boolean salirDES = false;
		boolean salirPass = false;
		boolean salirCertificado = false;
		int opcion;

		while (!salir) {

			System.out.println("1.- Cifrado/descifrado con RSA");
			System.out.println("2.- Cifrado/descifrado con AES");
			System.out.println("3.- Cifrado/descifrado con DES");
			System.out.println("4.- Hash de contrase�as");
			System.out.println("5.- Certificados");
			System.out.println("6.- Salir");

			try {

				System.out.print("Escribe una de las opciones: ");
				opcion = sc.nextInt();

				switch (opcion) {
				case 1:
					while (!salirRSA) {

						System.out.println("1.- Generar par de claves RSA");
						System.out.println("2.- Cifrar");
						System.out.println("3.- Descifrar");
						System.out.println("4.- Salir");

						try {

							System.out.print("Escribe una de las opciones: ");
							opcion = sc.nextInt();

							switch (opcion) {
							case 1:
								System.out.println("Se han genereado las claves publicKeyRSA.dat y privateKeyRSA.dat");
								clavesRSA();
								break;
							case 2:
								System.out.print("Introduce el archivo a cifrar: ");
								String archivo = sc.next();
								System.out.println(archivo);
								System.out.print("Introduce la clave publica para cifrar: ");
								String clavePublica = sc.next();
								System.out.println("Cifrando...");
								System.out.println("Se ha generado un archivo cifradoRSA.txt");
								long startTime = System.currentTimeMillis();
								cifradoRSA(archivo, clavePublica);
								long endTime = System.currentTimeMillis() - startTime;
								System.out.println("Ejecuci�n cifrado RSA: " + endTime);
								break;
							case 3:
								System.out.print("Introduce el archivo a descifrar: ");
								String archivo2 = sc.next();
								System.out.print("Introduce la clave privada para descifrar: ");
								String clavePrivada = sc.next();
								System.out.println("Descifrando...");
								System.out.println("Se ha generado un archivo descifradoRSA.txt");
								long startTime2 = System.currentTimeMillis();
								descifradoRSA(archivo2, clavePrivada);
								long endTime2 = System.currentTimeMillis() - startTime2;
								System.out.println("Ejecuci�n descifrado RSA: " + endTime2);
								break;
							case 4:
								salirRSA = true;
								break;
							default:
								System.out.println("Solo números entre 1 y 4");
							}

						} catch (InputMismatchException e) {
							System.out.println("Debes insertar un número");
							sc.next();
						}
					}
					break;
				case 2:
					while (!salirAES) {

						System.out.println("1.- Generar clave AES");
						System.out.println("2.- Cifrar");
						System.out.println("3.- Descifrar");
						System.out.println("4.- Salir");

						try {

							System.out.print("Escribe una de las opciones: ");
							opcion = sc.nextInt();

							switch (opcion) {
							case 1:
								System.out.println("Se ha generado la clave keyAES.dat");
								claveAES();
								break;
							case 2:
								System.out.print("Introduce el archivo a cifrar: ");
								String archivo = sc.next();
								System.out.print("Introduce la clave para cifrar: ");
								String clave = sc.next();
								System.out.println("Cifrando...");
								System.out.println("Se ha generado un archivo cifradoAES.txt");
								long startTime = System.currentTimeMillis();
								cifradoAES(archivo, clave);
								long endTime = System.currentTimeMillis() - startTime;
								System.out.println("Ejecuci�n cifrado AES: " + endTime);
								break;
							case 3:
								System.out.print("Introduce el archivo a descifrar: ");
								String archivo2 = sc.next();
								System.out.print("Introduce la clave para descifrar: ");
								String clave2 = sc.next();
								System.out.println("Descifrando...");
								System.out.println("Se ha generado un archivo descifradoAES.txt");
								long startTime2 = System.currentTimeMillis();
								descifradoAES(archivo2, clave2);
								long endTime2 = System.currentTimeMillis() - startTime2;
								System.out.println("Ejecuci�n descifrado AES: " + endTime2);
								break;
							case 4:
								salirAES = true;
								break;
							default:
								System.out.println("Solo números entre 1 y 4");
							}

						} catch (InputMismatchException e) {
							System.out.println("Debes insertar un número");
							sc.next();
						}
					}
					break;
				case 3:
					while (!salirDES) {

						System.out.println("1.- Generar clave DES");
						System.out.println("2.- Cifrar");
						System.out.println("3.- Descifrar");
						System.out.println("4.- Salir");

						try {

							System.out.print("Escribe una de las opciones: ");
							opcion = sc.nextInt();

							switch (opcion) {
							case 1:
								System.out.println("Se ha generado la clave keyDES.dat");
								claveDES();
								break;
							case 2:
								System.out.print("Introduce el archivo a cifrar: ");
								String archivo = sc.next();
								System.out.println(archivo);
								System.out.print("Introduce la clave para cifrar: ");
								String clavePublica = sc.next();
								System.out.println("Cifrando...");
								System.out.println("Se ha generado un archivo cifradoDES.txt");
								long startTime = System.currentTimeMillis();
								cifradoDES(archivo, clavePublica);
								long endTime = System.currentTimeMillis() - startTime;
								System.out.println("Ejecuci�n cifrado DES: " + endTime);
								break;
							case 3:
								System.out.print("Introduce el archivo a descifrar: ");
								String archivo2 = sc.next();
								System.out.print("Introduce la clave para descifrar: ");
								String clavePrivada = sc.next();
								System.out.println("Descifrando...");
								System.out.println("Se ha generado un archivo descifradoDES.txt");
								long startTime2 = System.currentTimeMillis();
								descifradoDES(archivo2, clavePrivada);
								long endTime2 = System.currentTimeMillis() - startTime2;
								System.out.println("Ejecuci�n cifrado DES: " + endTime2);
								break;
							case 4:
								salirDES = true;
								break;
							default:
								System.out.println("Solo números entre 1 y 4");
							}

						} catch (InputMismatchException e) {
							System.out.println("Debes insertar un número");
							sc.next();
						}
					}
					break;
				case 4:
					while (!salirPass) {

						System.out.println("1.- Generar hash con MD5");
						System.out.println("2.- Generar hash + salt con MD5 y SHA-1");
						System.out.println("3.- Salir");

						try {

							System.out.print("Escribe una de las opciones: ");
							opcion = sc.nextInt();

							switch (opcion) {
							case 1:
								System.out.print("Introduce la contrase�a: ");
								String pass = sc.next();
								System.out.println("Generando hash...");
								System.out.println("Se ha generado un archivo passMD5.txt con el hash resultante");
								hashMD5(pass);
								break;
							case 2:
								System.out.print("Introduce la contrase�a: ");
								String pass2 = sc.next();
								System.out.println("Generando hash salteado...");
								System.out.println("Se ha generado un archivo passSaltMD5.txt con el hash resultante");
								saltMD5(pass2);
								break;
							case 3:
								salirPass = true;
								break;
							default:
								System.out.println("Solo números entre 1 y 3");
							}

						} catch (InputMismatchException e) {
							System.out.println("Debes insertar un número");
							sc.next();
						}
					}
					break;
				case 5:
					while (!salirCertificado) {

						System.out.println("1.- Generar certificado");
						System.out.println("2.- Firmar con certificado");
						System.out.println("3.- Comprobar firma del certificado");
						System.out.println("4.- Salir");

						try {

							System.out.print("Escribe una de las opciones: ");
							opcion = sc.nextInt();

							switch (opcion) {
							case 1:
								System.out.print("Introduce la contrase�a: ");
								String pass = sc.next();
								System.out.println("Generando hash...");
								System.out.println("Se ha generado un archivo passMD5.txt con el hash resultante");
								hashMD5(pass);
								break;
							case 2:
								System.out.print("Introduce la contrase�a: ");
								String pass2 = sc.next();
								System.out.println("Generando hash salteado...");
								System.out.println("Se ha generado un archivo passSaltMD5.txt con el hash resultante");
								saltMD5(pass2);
								break;
							case 3:
								System.out.print("Introduce la contrase�a: ");
								String pass2 = sc.next();
								System.out.println("Generando hash salteado...");
								System.out.println("Se ha generado un archivo passSaltMD5.txt con el hash resultante");
								saltMD5(pass2);
								break;
							case 4:
								salirCertificado = true;
								break;
							default:
								System.out.println("Solo números entre 1 y 4");
							}

						} catch (InputMismatchException e) {
							System.out.println("Debes insertar un número");
							sc.next();
						}
					}
					break;
				case 6:
					salir = true;
					break;
				default:
					System.out.println("Solo números entre 1 y 6");
				}
			} catch (InputMismatchException e) {
				System.out.println("Debes insertar un número");
				sc.next();
			}
		}
	}

	private static byte[] getSalt() throws NoSuchAlgorithmException {
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		byte[] salt = new byte[16];
		sr.nextBytes(salt);
		return salt;
	}

	private static void saltMD5(String pass) throws Exception {
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(getSalt());
		byte[] digest = md.digest(pass.getBytes());

		String myHash = DatatypeConverter.printHexBinary(digest).toUpperCase();
		System.out.println(myHash);
		// Se escribe el texto
		FileWriter ficheroSalida = new FileWriter("passSaltMD5.txt");
		ficheroSalida
				.write("Se genera el hash: " + myHash + " sin saltear, facilmente comprobable en una rainbow table.");
		ficheroSalida.close();
	}

	private static void hashMD5(String pass) throws Exception {
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(pass.getBytes());
		byte[] digest = md.digest();

		String myHash = DatatypeConverter.printHexBinary(digest).toUpperCase();
		System.out.println(myHash);
		// Se escribe el texto
		FileWriter ficheroSalida = new FileWriter("passMD5.txt");
		ficheroSalida
				.write("Se genera el hash: " + myHash + " salteado, dificilmente comprobable en una rainbow table.");
		ficheroSalida.close();
	}

	private static void clavesRSA() throws Exception {

		// Generar el par de claves
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		// Se salva y recupera de fichero la clave publica
		saveKey(publicKey, "publickeyRSA.txt");
		// publicKey = loadPublicKey("publicKeyRSA.dat");

		// Se salva y recupera de fichero la clave privada
		saveKey(privateKey, "privatekeyRSA.txt");
		// privateKey = loadPrivateKey("privateKeyRSA.dat");

	}

	private static void cifradoRSA(String archivo, String clavePublica) throws Exception {

		// Obtener la clase para encriptar/desencriptar
		rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		// Texto a encriptar
		String text = "";
		File ficheroEntrada = new File(archivo);
		FileReader fr = new FileReader(ficheroEntrada);
		BufferedReader br = new BufferedReader(fr);
		String linea;

		while ((linea = br.readLine()) != null) {
			text = text + linea;
		}
		br.close();

		// Se encripta
		PublicKey publicKey = loadPublicKey(clavePublica);
		rsa.init(Cipher.ENCRYPT_MODE, publicKey);

		String encriptado = Base64.getEncoder().encodeToString(rsa.doFinal(text.getBytes("UTF-8")));

		// Escribimos el encriptado para verlo, con caracteres visibles
		FileWriter ficheroSalida = new FileWriter("cifradoRSA.txt");
		ficheroSalida.write(encriptado);
		ficheroSalida.close();
	}

	private static void descifradoRSA(String archivo, String clavePrivada) throws Exception {

		rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		String text = "";
		File ficheroEntrada = new File(archivo);
		FileReader fr = new FileReader(ficheroEntrada);
		BufferedReader br = new BufferedReader(fr);
		String linea;

		while ((linea = br.readLine()) != null) {
			text = text + linea;
		}
		br.close();

		// Se desencripta
		PrivateKey privateKey = loadPrivateKey(clavePrivada);
		rsa.init(Cipher.DECRYPT_MODE, privateKey);

		String desencriptado = new String(rsa.doFinal(Base64.getDecoder().decode(text)));

		// Se escribe el texto desencriptado
		FileWriter ficheroSalida = new FileWriter("descifradoRSA.txt");
		ficheroSalida.write(desencriptado);
		ficheroSalida.close();
	}

	private static void claveAES() throws Exception {

		// Generamos una clave de 128 bits adecuada para AES
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		Key key = keyGenerator.generateKey();

		// Alternativamente, una clave que queramos que tenga al menos 16 bytes
		// y nos quedamos con los bytes 0 a 15
		// key = new SecretKeySpec("una clave de 16 bytes".getBytes(), 0, 16, "AES");

		// Se salva y recupera de fichero la clave
		saveKey(key, "keyAES.dat");
	}

	private static void cifradoAES(String archivo, String clave) throws Exception {

		// Texto a encriptar
		String text = "";
		File ficheroEntrada = new File(archivo);
		FileReader fr = new FileReader(ficheroEntrada);
		BufferedReader br = new BufferedReader(fr);
		String linea;

		while ((linea = br.readLine()) != null) {
			text = text + linea;
		}
		br.close();

		// Se obtiene un cifrador AES

		Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");

		// Se inicializa para encriptacion y se encripta el texto,
		// que debemos pasar como bytes
		Key key = loadKey(clave);
		aes.init(Cipher.ENCRYPT_MODE, key);
		String encriptado = Base64.getEncoder().encodeToString(aes.doFinal(text.getBytes("UTF-8")));

		// Se escribe byte a byte en hexadecimal el texto
		// encriptado para ver su pinta.
		FileWriter ficheroSalida = new FileWriter("cifradoAES.txt");
		ficheroSalida.write(encriptado);
		ficheroSalida.close();
	}

	private static void descifradoAES(String archivo, String clave) throws Exception {

		// Se obtiene un cifrador AES

		Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");

		String text = "";
		File ficheroEntrada = new File(archivo);
		FileReader fr = new FileReader(ficheroEntrada);
		BufferedReader br = new BufferedReader(fr);
		String linea;

		while ((linea = br.readLine()) != null) {
			text = text + linea;
		}
		br.close();

		// Se inicializa el cifrador para desencriptar, con la
		// misma clave y se desencripta
		Key key = loadKey(clave);
		aes.init(Cipher.DECRYPT_MODE, key);
		String desencriptado = new String(aes.doFinal(Base64.getDecoder().decode(text)));

		// Se escribe byte a byte en hexadecimal el texto
		// encriptado para ver su pinta.
		FileWriter ficheroSalida = new FileWriter("descifradoAES.txt");
		ficheroSalida.write(desencriptado);
		ficheroSalida.close();

	}

	private static void claveDES() throws Exception {

		KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
		keyGenerator.init(56);
		SecretKey key = keyGenerator.generateKey();

		// Alternativamente, una clave que queramos que tenga al menos 16 bytes
		// y nos quedamos con los bytes 0 a 15
		// key = new SecretKeySpec("una clave de 16 bytes".getBytes(), 0, 16, "AES");

		// Se salva y recupera de fichero la clave
		saveKey(key, "keyDES.dat");
	}

	private static void cifradoDES(String archivo, String clave) throws Exception {

		// Texto a encriptar
		String text = "";
		File ficheroEntrada = new File(archivo);
		FileReader fr = new FileReader(ficheroEntrada);
		BufferedReader br = new BufferedReader(fr);
		String linea;

		while ((linea = br.readLine()) != null) {
			text = text + linea;
		}
		br.close();

		// Se obtiene un cifrador AES

		Cipher des = Cipher.getInstance("DES/ECB/PKCS5Padding");

		// Se inicializa para encriptacion y se encripta el texto,
		// que debemos pasar como bytes
		SecretKey key = loadSecretKey(clave);
		des.init(Cipher.ENCRYPT_MODE, key);
		String encriptado = Base64.getEncoder().encodeToString(des.doFinal(text.getBytes("UTF-8")));

		// Se escribe byte a byte en hexadecimal el texto
		// encriptado para ver su pinta.
		FileWriter ficheroSalida = new FileWriter("cifradoDES.txt");
		ficheroSalida.write(encriptado);
		ficheroSalida.close();
	}

	private static void descifradoDES(String archivo, String clave) throws Exception {

		// Se obtiene un cifrador AES

		Cipher des = Cipher.getInstance("DES/ECB/PKCS5Padding");

		String text = "";
		File ficheroEntrada = new File(archivo);
		FileReader fr = new FileReader(ficheroEntrada);
		BufferedReader br = new BufferedReader(fr);
		String linea;

		while ((linea = br.readLine()) != null) {
			text = text + linea;
		}
		br.close();

		// Se inicializa el cifrador para desencriptar, con la
		// misma clave y se desencripta
		SecretKey key = loadSecretKey(clave);
		des.init(Cipher.DECRYPT_MODE, key);
		String desencriptado = new String(des.doFinal(Base64.getDecoder().decode(text)));

		// Se escribe byte a byte en hexadecimal el texto
		// encriptado para ver su pinta.
		FileWriter ficheroSalida = new FileWriter("descifradoDES.txt");
		ficheroSalida.write(desencriptado);
		ficheroSalida.close();

	}

	private static PublicKey loadPublicKey(String fileName) throws Exception {

		FileInputStream fis = new FileInputStream(fileName);
		int numBytes = fis.available();
		byte[] bytes = new byte[numBytes];
		fis.read(bytes);
		fis.close();

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		KeySpec keySpec = new X509EncodedKeySpec(bytes);
		PublicKey keyFromBytes = keyFactory.generatePublic(keySpec);
		return keyFromBytes;

	}

	private static PrivateKey loadPrivateKey(String fileName) throws Exception {

		FileInputStream fis = new FileInputStream(fileName);
		int numBytes = fis.available();
		byte[] bytes = new byte[numBytes];
		fis.read(bytes);
		fis.close();

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		KeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
		PrivateKey keyFromBytes = keyFactory.generatePrivate(keySpec);
		return keyFromBytes;

	}

	private static Key loadKey(String fileName) throws Exception {
		FileInputStream fis = new FileInputStream(fileName);
		int numBytes = fis.available();
		byte[] bytes = new byte[numBytes];
		fis.read(bytes);
		fis.close();

		Key key = new SecretKeySpec(bytes, "AES");
		return key;
	}

	private static void saveKey(Key key, String fileName) throws Exception {

		byte[] publicKeyBytes = key.getEncoded();
		FileOutputStream fos = new FileOutputStream(fileName);
		fos.write(publicKeyBytes);
		fos.close();

	}

	private static SecretKey loadSecretKey(String fileName) throws Exception {
		FileInputStream fis = new FileInputStream(fileName);
		int numBytes = fis.available();
		byte[] bytes = new byte[numBytes];
		fis.read(bytes);
		fis.close();

		SecretKey key = new SecretKeySpec(bytes, "DES");
		return key;
	}
	
	private static void createCertificate(String commonName, String organizationalUnit, String organization, String country) throws Exception {
		String CN  = commonName;
		String OU = organizationalUnit;
		String O = organization;
		String C = country;
		
		int keySize = 2048;
		int validDays = 365;
		
		//CertificateFactory cf = CertificateFactory.getInstance("X.509");
		//X500Principal datos = new X500Principal("CN="+CN+",OU="+OU+",O="+O+",C="+C);
		//X509Certificate certificado = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(datos));
		CertAndKeyGen certGen = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
		X509Certificate certificado = certGen.getSelfCertificate();
	}
}