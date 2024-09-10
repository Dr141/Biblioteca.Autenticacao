namespace Identity.Application.DTOs.Response;

public class UsuariosResponse
{
    public bool Sucesso => Erros.Count == 0;

    public List<string> Erros { get; private set; }

    public Dictionary<string, bool> Usuarios { get; private set; }


    public UsuariosResponse()
    {
        Erros = new List<string>();
        Usuarios = new Dictionary<string, bool>();
    }

    /// <summary>
    /// Método para adicionar erro na lista.
    /// </summary>
    /// <param name="erro">Fornecer a mensagem de erro do tipo <see cref="string"/>.</param>
    public void AdicionarErro(string erro) =>
        Erros.Add(erro);

    /// <summary>
    /// Método para adicionar usuário na lista.
    /// </summary>
    /// <param name="email">Fornecer o e-mail do usuário com o tipo <see cref="string"/>.</param>
    /// <param name="emailConfirmado">Informar se o e-mail foi confirmado.</param>
    public void AdicionarUsuario(string email, bool emailConfirmado) =>
        Usuarios.Add(email, emailConfirmado);
}
