using System.Text;
using System.Security.Cryptography;

string[] keys =
[
    "68544020247570407220244063724074",
    "54684020247570407220244063724074",
    "54684020247570407220244063727440"
];

const string initializationVector = "656e6372797074696f6e496e74566563";
const string encryptedMessage = "876b4e970c3516f333bcf5f16d546a87aaeea5588ead29d213557efc1903997e";
const string sha256CorrectKeyHash = "f28fe539655fd6f7275a09b7c3508a3f81573fc42827ce34ddf1ec8d5c2421c3";

var correctKey = FindCorrectKey(keys, sha256CorrectKeyHash);

if (correctKey is null)
{
    Console.WriteLine("Can't find correct sha256 key from list provided");

    return;
}

Console.WriteLine($"Found correct aes key: {correctKey}");

var correctKeyBytes = Convert.FromHexString(correctKey);

var decryptedMessageBytes = DecryptMessageWithAes(
    encryptedMessage,
    Convert.FromHexString(initializationVector),
    correctKeyBytes
);

CreateSignature(decryptedMessageBytes);

return;

static string? FindCorrectKey(string[] keys, string sha256CorrectKeyHash)
{
    var correctKey = keys.FirstOrDefault(key =>
    {
        var bytes = Convert.FromHexString(key);

        var possibleCorrectKeyBytes = SHA256.HashData(bytes);

        var hashHex = Convert.ToHexString(possibleCorrectKeyBytes).ToLower();

        return hashHex == sha256CorrectKeyHash;
    });

    return correctKey;
}

static byte[] DecryptMessageWithAes(string encryptedMessage, byte[] iv, byte[] key)
{
    var encryptedMessageBytes = Convert.FromHexString(encryptedMessage);

    using var aes = Aes.Create();
    aes.Key = key;

    var decryptedMessageBytes = aes.DecryptCbc(
        encryptedMessageBytes,
        iv
    );

    var decryptedMessage = Encoding.UTF8.GetString(decryptedMessageBytes);

    Console.WriteLine($"Message decrypted: {decryptedMessage}");

    return decryptedMessageBytes;
}

static void CreateSignature(byte[] messageBytes)
{
    using var ecdsa = ECDsa.Create();

    var publicKey = ecdsa.ExportSubjectPublicKeyInfoPem();
    Console.WriteLine("Public Key:");
    Console.WriteLine(publicKey);
    
    var privateKey = ecdsa.ExportPkcs8PrivateKeyPem();
    Console.WriteLine("Private Key:");
    Console.WriteLine(privateKey);

    var signature = ecdsa.SignData(messageBytes, HashAlgorithmName.SHA256);

    Console.WriteLine("Digital Signature (Base64):");
    Console.WriteLine(Convert.ToBase64String(signature));
    Console.WriteLine();

    var isValid = ecdsa.VerifyData(messageBytes, signature, HashAlgorithmName.SHA256);
    Console.WriteLine($"Signature valid: {isValid}");
}