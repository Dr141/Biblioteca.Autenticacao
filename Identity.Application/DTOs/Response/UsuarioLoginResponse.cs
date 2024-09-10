using System.Text.Json.Serialization;

namespace Identity.Application.DTOs.Response;

public class UsuarioLoginResponse
{
    public bool Sucesso => Erros.Count == 0;

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string AccessToken { get; private set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string RefreshToken { get; private set; }

    public List<string> Erros { get; private set; }

    public UsuarioLoginResponse() =>
        Erros = new List<string>();

    public UsuarioLoginResponse(bool sucesso, string accessToken, string refreshToken) : this()
    {
        AccessToken = accessToken;
        RefreshToken = refreshToken;
    }

    /// <summary>
    /// Método para adicionar erro na lista.
    /// </summary>
    /// <param name="erro">Fornecer a mensagem de erro do tipo <see cref="string"/>.</param>
    public void AdicionarErro(string erro) =>
        Erros.Add(erro);

    /// <summary>
    /// Método para adicionar uma lista de erros.
    /// </summary>
    /// <param name="erros">Fornecer um <see cref="IEnumerable"/> do tipo <see cref="string"/>.</param>
    public void AdicionarErros(IEnumerable<string> erros) =>
        Erros.AddRange(erros);
}