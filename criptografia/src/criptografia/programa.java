package criptografia;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class programa {

	private static Cipher rsa;
	
	public static void main(String[] args) throws Exception {
		
		// Generar el par de claves
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		// Se salva y recupera de fichero la clave publica
		saveKey(publicKey, "publickey.dat");
		//publicKey = loadPublicKey("publicKey.dat");
		
		// Se salva y recupera de fichero la clave privada
		saveKey(privateKey, "privatekey.dat");
		//privateKey = loadPrivateKey("privateKey.dat");
		
		// Obtener la clase para encriptar/desencriptar
		rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		
		// Texto a encriptar
		String text = "Text to encrypt";
		
		// Se encripta
		rsa.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encriptado = rsa.doFinal(text.getBytes());
		
		// Escribimos el encriptado para verlo, con caracteres visibles
		for (byte b: encriptado) {
			System.out.print(Integer.toHexString(0xFF & b));
		}
		System.out.println();
		
		// Se desencripta
		rsa.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] bytesDesencriptados = rsa.doFinal(encriptado);
		String textoDesencriptado = new String(bytesDesencriptados);
		
		// Se escribe el texto desencriptado
		System.out.println(textoDesencriptado);
		
		
		// -----------------------------------------------------------------
		
		// Generamos una clave de 128 bits adecuada para AES
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		Key key = keyGenerator.generateKey();
		
		// Alternativamente, una clave que queramos que tenga al menos 16 bytes
		// y nos quedamos con los bytes 0 a 15
		key = new SecretKeySpec("una clave de 16 bytes".getBytes(),0, 16, "AES");
		
		// Ver como se puede guardar esta clave en un fichero y recuperarla
		// posteriormente en la clase RSAAsymetricCrypto.java
		
		// Texto a encriptar
		String texto = "Este es el texto que queremos encriptar";
		
		// Se obtiene un cifrador AES
		Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
		
		// Se inicializa para encriptacion y se encripta el texto,
		// que debemos pasar como bytes
		aes.init(Cipher.ENCRYPT_MODE, key);
		encriptado = aes.doFinal(texto.getBytes());
		
		// Se escribe byte a byte en hexadecimal el texto
		// encriptado para ver su pinta.
		for (byte b: encriptado) {
			System.out.print(Integer.toHexString(0xFF & b));
		}
		System.out.println();
		
		// Se inicializa el cifrador para desencriptar, con la
		// misma clave y se desencripta
		aes.init(Cipher.DECRYPT_MODE, key);
		byte[] desencriptado = aes.doFinal(encriptado);
		
		// Texto obtenido, igual al original
		System.out.println(new String(desencriptado));
		
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
	
	private static void saveKey(Key key, String fileName) throws Exception {
		
		byte[] publicKeyBytes = key.getEncoded();
		FileOutputStream fos = new FileOutputStream(fileName);
		fos.write(publicKeyBytes);
		fos.close();
		
	}
	
}