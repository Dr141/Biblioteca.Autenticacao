using Identity.Application.DTOs.Request;
using Identity.Application.DTOs.Response;

namespace Identity.Application.Interfaces.ServicesIdentity;

public interface IIdentityService
{
    Task<UsuarioCadastroResponse> CadastrarUsuario(UsuarioCadastroRequest usuarioCadastro);
    Task<UsuarioLoginResponse> Login(UsuarioLoginRequest usuarioLogin);
    Task<UsuarioCadastroResponse> AtualizarPermisao(UsuarioAtualizarPermisaoRequest usuarioPermisao);
    Task<UsuarioCadastroResponse> AtualizarSenha(UsuarioAtualizarSenhaResquest usuarioLoginAtualizarSenha);
    Task<UsuarioCadastroResponse> AtualizarSenhaInterno(UsuarioCadastroRequest usuarioLoginAtualizarSenha);
}
