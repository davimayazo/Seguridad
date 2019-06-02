package criptografia;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.InputMismatchException;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class programa {

	public static Cipher rsa;
	public static Cipher aes;

	public static void main(String[] args) throws Exception {

		Scanner sc = new Scanner(System.in);
		boolean salir = false;
		boolean salirRSA = false;
		boolean salirAES = false;
		boolean salirDES = false;
		int opcion;

		while (!salir) {

			System.out.println("1.- Cifrado/descifrado con RSA");
			System.out.println("2.- Cifrado/descifrado con AES");
			System.out.println("3.- Salir");

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
								cifradoRSA(archivo, clavePublica);
								break;
							case 3:
								System.out.print("Introduce el archivo a descifrar: ");
								String archivo2 = sc.next();
								System.out.print("Introduce la clave privada para descifrar: ");
								String clavePrivada = sc.next();
								System.out.println("Descifrando...");
								System.out.println("Se ha generado un archivo descifradoRSA.txt");
								descifradoRSA(archivo2, clavePrivada);
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
								System.out.println("Se ha generado la clave key.dat");
								claveAES();
								break;
							case 2:
								System.out.print("Introduce el archivo a cifrar: ");
								String archivo = sc.next();
								System.out.print("Introduce la clave para cifrar: ");
								String clave = sc.next();
								System.out.println("Cifrando...");
								System.out.println("Se ha generado un archivo cifradoAES.txt");
								cifradoAES(archivo, clave);
								break;
							case 3:
								System.out.print("Introduce el archivo a descifrar: ");
								String archivo2 = sc.next();
								System.out.print("Introduce la clave para descifrar: ");
								String clave2 = sc.next();
								System.out.println("Descifrando...");
								System.out.println("Se ha generado un archivo descifradoAES.txt");
								descifradoAES(archivo2, clave2);
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
					salir = true;
					break;
				default:
					System.out.println("Solo números entre 1 y 3");
				}
			} catch (InputMismatchException e) {
				System.out.println("Debes insertar un número");
				sc.next();
			}

		}
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

		// Se encripta
		PublicKey publicKey = loadPublicKey(clavePublica);
		rsa.init(Cipher.ENCRYPT_MODE, publicKey);

		byte[] encriptado = rsa.doFinal(text.getBytes());

		// Escribimos el encriptado para verlo, con caracteres visibles
		FileWriter ficheroSalida = new FileWriter("cifradoRSA.txt");
		for (byte b : encriptado) {
			ficheroSalida.write(Integer.toHexString(0xFF & b));
		}
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

		// Se desencripta
		PrivateKey privateKey = loadPrivateKey(clavePrivada);
		rsa.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] bytesDesencriptados = rsa.doFinal(text.getBytes());
		String textoDesencriptado = new String(bytesDesencriptados);

		// Se escribe el texto desencriptado
		FileWriter ficheroSalida = new FileWriter("cifradoRSA.txt");
		PrintWriter pw = new PrintWriter(ficheroSalida);
		pw.println(textoDesencriptado);

	}

	private static void claveAES() throws Exception {

		// Generamos una clave de 128 bits adecuada para AES
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		Key key = keyGenerator.generateKey();

		// Alternativamente, una clave que queramos que tenga al menos 16 bytes
		// y nos quedamos con los bytes 0 a 15
		//key = new SecretKeySpec("una clave de 16 bytes".getBytes(), 0, 16, "AES");

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

		// Se obtiene un cifrador AES

		Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");

		// Se inicializa para encriptacion y se encripta el texto,
		// que debemos pasar como bytes
		Key key = loadKey(clave);
		aes.init(Cipher.ENCRYPT_MODE, key);
		byte[] encriptado = aes.doFinal(text.getBytes());
		
		// Se escribe byte a byte en hexadecimal el texto
		// encriptado para ver su pinta.
		FileWriter ficheroSalida = new FileWriter("cifradoAES.txt");
		for (byte b : encriptado) {
			ficheroSalida.write(Integer.toHexString(0xFF & b));
		}
		ficheroSalida.close();
	}

	private static void descifradoAES(String archivo, String clave) throws Exception {

		String text = "";
		File ficheroEntrada = new File(archivo);
		FileReader fr = new FileReader(ficheroEntrada);
		BufferedReader br = new BufferedReader(fr);
		String linea;

		while ((linea = br.readLine()) != null) {
			text = text + linea;
		}

		// Se inicializa el cifrador para desencriptar, con la
		// misma clave y se desencripta
		Key key = loadKey(clave);
		aes.init(Cipher.DECRYPT_MODE, key);
		byte[] desencriptado = aes.doFinal(text.getBytes());

		// Texto obtenido, igual al original
		FileWriter ficheroSalida = new FileWriter("descifradoAES.txt");
		PrintWriter pw = new PrintWriter(ficheroSalida);
		pw.println(desencriptado);

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

}