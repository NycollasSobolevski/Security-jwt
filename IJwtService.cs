public interface IJwtService
{
    string GetToken<T>(T payload);
    T Validate<T>(string jwt)
        where T : class;
}