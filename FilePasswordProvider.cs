using System.IO;
namespace Security_jwt;

public class FilePasswordProvider : IPasswordProvider
{
    string password;
    public FilePasswordProvider(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("Password file not found");

        this.password = File.ReadAllText(path);
    }
    public string ProvidePassword()
        => this.password;
}