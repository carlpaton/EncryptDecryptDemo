using System.Security.Cryptography;
using System.Text;

// In REAL application, NEVER hardcode this.
string key = "MySuperSecretKey"; 
string iv = "MyInitialVector";

var service = new AesEncryptionService(key, iv);

string originalText = "This is something Id like to Encrypt for network transport.";
Console.WriteLine($"OriginalText:\n {originalText}");
Console.WriteLine("--------------------------------------------------------------\n");

byte[] dataToEncrypt = Encoding.UTF8.GetBytes(originalText);

byte[] encryptedData = service.Encrypt(dataToEncrypt);
string encryptedBase64 = Convert.ToBase64String(encryptedData); // Good for storage/transmission

Console.WriteLine($"Encrypted (and converted Base64 for storage/transmission):\n {encryptedBase64}");
Console.WriteLine("--------------------------------------------------------------\n");

byte[] decryptedData = service.Decrypt(encryptedData);
string decryptedText = Encoding.UTF8.GetString(decryptedData);

Console.WriteLine($"Decrypted:\n {decryptedText}");

Console.ReadKey();




public class AesEncryptionService(string key, string iv)
{
    private readonly byte[] _key = SHA256.HashData(Encoding.UTF8.GetBytes(key));
    private readonly byte[] _initializationVector = SHA256.HashData(Encoding.UTF8.GetBytes(iv)).Take(16).ToArray(); // nonce (number used once)

    public byte[] Encrypt(byte[] data)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _initializationVector;
        aes.Padding = PaddingMode.PKCS7; // Explicitly set padding

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream();
        using var stream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        stream.Write(data, 0, data.Length);
        stream.FlushFinalBlock();
        return ms.ToArray();
    }

    public byte[] Decrypt(byte[] cipherText)
    {
        using var aesAlg = Aes.Create();
        aesAlg.Key = _key;
        aesAlg.IV = _initializationVector;
        aesAlg.Padding = PaddingMode.PKCS7; // Explicitly set padding

        using var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
        using var msDecrypt = new MemoryStream(cipherText);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var msPlain = new MemoryStream();
        csDecrypt.CopyTo(msPlain); // Simpler way to read the entire stream, could also use StreamReader
        return msPlain.ToArray();
    }
}