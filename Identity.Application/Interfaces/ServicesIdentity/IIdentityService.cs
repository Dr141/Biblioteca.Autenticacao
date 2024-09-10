using Identity.Application.DTOs.Request;
using Identity.Application.DTOs.Response;

namespace Identity.Application.Interfaces.ServicesIdentity;

/// <summary>
/// Interface para padronizar a autenticação com identity.
/// </summary>
public interface IIdentityService
{
    Task<UsuarioCadastroResponse> CadastrarUsuario(UsuarioCadastroRequest usuarioCadastro);
    Task<UsuarioLoginResponse> Login(UsuarioLoginRequest usuarioLogin);
    Task<UsuarioCadastroResponse> AtualizarPermisao(UsuarioAtualizarPermisaoRequest usuarioPermisao);
    Task<UsuarioCadastroResponse> AtualizarSenha(UsuarioAtualizarSenhaResquest usuarioLoginAtualizarSenha);
    Task<UsuarioCadastroResponse> AtualizarSenhaInterno(UsuarioCadastroRequest usuarioLoginAtualizarSenha);
    Task<UsuariosResponse> ObterTodosUsuarios();
}
