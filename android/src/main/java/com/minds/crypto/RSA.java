package com.minds.crypto;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.security.cert.X509Certificate;

import java.io.IOException;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.pkcs.RSAPublicKey;
import org.spongycastle.asn1.pkcs.RSAPrivateKey;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x509.RSAPublicKeyStructure;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemWriter;
import org.spongycastle.util.io.pem.PemReader;
import org.spongycastle.asn1.pkcs.RSAPublicKey;
import org.spongycastle.openssl.PEMParser;

import static android.security.keystore.KeyProperties.*;
import static java.nio.charset.StandardCharsets.UTF_8;

public class RSA {

    public static final String ALGORITHM = "RSA";

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public RSA() {
    }

    public void setPublicKey(String publicKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        publicKey = publicKey.replaceAll("(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)", "");
        byte[] publickeyRaw = Base64.decode(publicKey, Base64.DEFAULT);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publickeyRaw);
        this.publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public void setPrivateKey(String privateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        privateKey = privateKey.replaceAll("(-+BEGIN PRIVATE KEY-+\\r?\\n|-+END PRIVATE KEY-+\\r?\\n?)", "");
        byte[] privatekeyRaw = Base64.decode(privateKey, Base64.DEFAULT);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privatekeyRaw);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        this.privateKey = keyFactory.generatePrivate(keySpec);
    }

    // This function will be called by encrypt and encrypt64
    private byte[] encrypt(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        String encodedMessage = null;
        final Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        byte[] cipherBytes = cipher.doFinal(data);
        return cipherBytes;
    }

    // Base64 input
    public String encrypt64(String b64Message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        byte[] data = Base64.decode(b64Message, Base64.DEFAULT);
        byte[] cipherBytes = encrypt(data);
        return Base64.encodeToString(cipherBytes, Base64.DEFAULT);
    }

    // UTF-8 input
    public String encrypt(String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        byte[] data = message.getBytes(UTF_8);
        byte[] cipherBytes = encrypt(data);
        return Base64.encodeToString(cipherBytes, Base64.DEFAULT);
    }

    private byte[] decrypt(byte[] cipherBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        String message = null;
        final Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        byte[] data = cipher.doFinal(cipherBytes);
        return data;
    }

    // UTF-8 input
    public String decrypt(String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        byte[] cipherBytes = Base64.decode(message, Base64.DEFAULT);
        byte[] data = decrypt(cipherBytes);
        return new String(data, UTF_8);
    }

    // Base64 input
    public String decrypt64(String b64message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        byte[] cipherBytes = Base64.decode(b64message, Base64.DEFAULT);
        byte[] data = decrypt(cipherBytes);
        return Base64.encodeToString(data, Base64.DEFAULT);
    }

    private String sign(byte[] messageBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        Signature privateSignature = Signature.getInstance("SHA512withRSA");
        privateSignature.initSign(this.privateKey);
        privateSignature.update(messageBytes);
        byte[] signature = privateSignature.sign();
        return Base64.encodeToString(signature, Base64.DEFAULT);
    }

    // b64 message
    public String sign64(String b64message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        byte[] messageBytes = Base64.decode(b64message, Base64.DEFAULT);
        return sign(messageBytes);
    }

    //utf-8 message
    public String sign(String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        byte[] messageBytes = message.getBytes(UTF_8);
        return sign(messageBytes);
    }

    private boolean verify(byte[] signatureBytes, byte[] messageBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance("SHA512withRSA");
        publicSignature.initVerify(this.publicKey);
        publicSignature.update(messageBytes);
        return publicSignature.verify(signatureBytes);
    }

    // b64 message
    public boolean verify64(String signature, String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance("SHA512withRSA");
        publicSignature.initVerify(this.publicKey);
        byte[] messageBytes = Base64.decode(message, Base64.DEFAULT);
        byte[] signatureBytes = Base64.decode(signature, Base64.DEFAULT);
        return verify(signatureBytes, messageBytes);
    }

    // utf-8 message
    public boolean verify(String signature, String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance("SHA512withRSA");
        publicSignature.initVerify(this.publicKey);
        byte[] messageBytes = message.getBytes(UTF_8);
        byte[] signatureBytes = Base64.decode(signature, Base64.DEFAULT);
        return verify(signatureBytes, messageBytes);
    }
}
