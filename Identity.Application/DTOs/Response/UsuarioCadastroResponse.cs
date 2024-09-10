namespace Identity.Application.DTOs.Response;

public class UsuarioCadastroResponse
{
    public bool Sucesso { get; private set; }
    public List<string> Erros { get; private set; }

    public UsuarioCadastroResponse() =>
        Erros = new List<string>();

    public UsuarioCadastroResponse(bool sucesso = true) : this() =>
        Sucesso = sucesso;
        
    /// <summary>
    /// Método para adicionar uma lista de erros.
    /// </summary>
    /// <param name="erros">Fornecer um <see cref="IEnumerable"/> do tipo <see cref="string"/>.</param>
    public void AdicionarErros(IEnumerable<string> erros) =>
        Erros.AddRange(erros);

    /// <summary>
    /// Método para adicionar erro na lista.
    /// </summary>
    /// <param name="erro">Fornecer a mensagem de erro do tipo <see cref="string"/>.</param>
    public void AdicionarErro(string erro) =>
        Erros.Add(erro);
}