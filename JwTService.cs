using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using System;
namespace Security_jwt;

public class JwTService : IJwtService
{
    IPasswordProvider provider;
    public JwTService(IPasswordProvider provider)
    {
        this.provider = provider;
    }

    public string GetToken<T>(T obj)
    {
        var header = this.getJsonHeader();
        
        var json = JsonSerializer.Serialize(obj);
        var payload = this.jsonToBase64(json);
        var signature = this.getSignature(header, payload);

        return $"{header}.{payload}.{signature}";
    }

    public T Validate<T>(string jwt)
        where T : class
    {
        var separator = jwt.Split('.');
        var header = separator[0];
        var payload = separator[1];
        var signature = separator[2];
        
        var realSig = this.getSignature(header, payload);

        if (realSig != signature)  
            return null;
        
        return JsonSerializer.Deserialize<T>(this.base64toJson(jwt));
    }

    private string base64toJson(string base64)
    {
        var addedPadding = addPadding(base64);
        var bytes = Convert.FromBase64String(addedPadding);
        var json = Encoding.UTF8.GetString(bytes);
        return json;
    }
    private string getSignature(string header, string payload)
    {
        var password = this.provider.ProvidePassword();
        var data = header + payload + password;
        var signature = this.applyHash(data);
        return signature;
    }
    private string applyHash(string str)
    {
        using var sha = SHA256.Create();                 // cria algoritimo de Hash
        var bytes = Encoding.UTF8.GetBytes(str);         // 
        var hashBytes = sha.ComputeHash(bytes);
        var hash = Convert.ToBase64String(hashBytes);
        var unpadHash = this.removePadding(hash);
        return unpadHash;
    }
    private string getJsonHeader()
    {
        string header  = """
            {
                "alg": "HS256",
                "typ": "JWT"
            }
            """;
        var base64 = this.jsonToBase64(header);
        return base64;
    }
    private string jsonToBase64(string json)
    {
        var bytes =  Encoding.UTF8.GetBytes(json);
        var base64 = Convert.ToBase64String(bytes);       
        var unpadBase64 = this.removePadding(base64);
        return unpadBase64;
    }
    private string removePadding(string base64)
    {
        var unpaddingBase64 = base64.Replace("=", "");
        return unpaddingBase64;
    }
    private string addPadding(string base64)
    {
        int bits = 6 * base64.Length;
        while(bits % 8 != 0)
        {
            bits += 6;
            base64 += "=";
        }
        return base64;
    }
}