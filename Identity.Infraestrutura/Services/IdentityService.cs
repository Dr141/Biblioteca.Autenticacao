using Identity.Application.DTOs.Request;
using Identity.Application.DTOs.Response;
using Identity.Application.Interfaces.ServicesIdentity;
using Identity.Infraestrutura.Configurations;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Identity.Infraestrutura.Services;

/// <summary>
/// Classe para gerenciar autenticação com identity.
/// </summary>
public class IdentityService : IIdentityService
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly JwtOptions _jwtOptions;
    private readonly RoleManager<IdentityRole> _roleManager;

    /// <summary>
    /// Contrutor para inciar a classe <see cref="IdentityService"/>
    /// com todos os objetos necessário.
    /// </summary>
    /// <param name="signInManager">Aguarda um objeto <see cref="SignInManager"/> do tipo <see cref="IdentityUser"/></param>
    /// <param name="userManager">Aguarda um objeto <see cref="UserManager"/> do tipo <see cref="IdentityUser"/></param>
    /// <param name="jwtOptions">Augarda um objeto <see cref="IOptions"/> do tipo <see cref="JwtOptions"/></param>
    public IdentityService(SignInManager<IdentityUser> signInManager,
                           UserManager<IdentityUser> userManager,
                           IOptions<JwtOptions> jwtOptions,
                           RoleManager<IdentityRole> roleManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _jwtOptions = jwtOptions.Value;
        _roleManager = roleManager;
    }

    /// <summary>
    /// Altera a senha de usuário.
    /// </summary>
    /// <param name="usuarioLoginAtualizarSenha">Fornecer um objeto do tipo <see cref="UsuarioAtualizarSenhaResquest"/>.</param>
    /// <returns>
    /// A <see cref="Task"/> é uma operação assícrona que retorna um <see cref="UsuarioCadastroResponse"/>
    /// ao final da operação.
    /// </returns>
    public async Task<UsuarioCadastroResponse> AtualizarSenha(UsuarioAtualizarSenhaResquest usuarioLoginAtualizarSenha)
    {
        var user = await _userManager.FindByEmailAsync(usuarioLoginAtualizarSenha.Email);

        if(user is IdentityUser)
        {
            var result = await _userManager.ChangePasswordAsync(user, usuarioLoginAtualizarSenha.SenhaAtual, usuarioLoginAtualizarSenha.NovaSenha);
            var usuarioResponse = new UsuarioCadastroResponse(result.Succeeded);
            
            if (!result.Succeeded && result.Errors.Count() > 0)
                usuarioResponse.AdicionarErros(result.Errors.Select(r => r.Description));

            return usuarioResponse;
        }

        var usuarioCadastroResponse = new UsuarioCadastroResponse();
        usuarioCadastroResponse.AdicionarErro($"Usuário com e-mail {usuarioLoginAtualizarSenha.Email}, não foi encontrado.");

        return usuarioCadastroResponse;
    }

    /// <summary>
    /// Alterar a senha sem necessidade de informar a senha atual.
    /// </summary>
    /// <param name="usuarioLoginAtualizarSenha">Fornecer um objeto do tipo <see cref="UsuarioCadastroRequest"/></param>
    /// <returns>
    /// A <see cref="Task"/> é uma operação assícrona que retorna um <see cref="UsuarioCadastroResponse"/>
    /// ao final da operação.
    /// </returns>
    public async Task<UsuarioCadastroResponse> AtualizarSenhaInterno(UsuarioCadastroRequest usuarioLoginAtualizarSenha)
    {
        var user = await _userManager.FindByEmailAsync(usuarioLoginAtualizarSenha.Email);

        if (user is IdentityUser)
        {
            await _userManager.RemovePasswordAsync(user);
            var result = await _userManager.AddPasswordAsync(user, usuarioLoginAtualizarSenha.Senha);
            var usuarioResponse = new UsuarioCadastroResponse(result.Succeeded);

            if (!result.Succeeded && result.Errors.Count() > 0)
                usuarioResponse.AdicionarErros(result.Errors.Select(r => r.Description));

            return usuarioResponse;
        }

        var usuarioCadastroResponse = new UsuarioCadastroResponse();
        usuarioCadastroResponse.AdicionarErro($"Usuário com e-mail {usuarioLoginAtualizarSenha.Email}, não foi encontrado.");

        return usuarioCadastroResponse;
    }

    /// <summary>
    /// Atualiza a permissão do usuário.
    /// </summary>
    /// <param name="usuarioPermisao">Fornecer um objeto do tipo <see cref="UsuarioAtualizarPermisaoRequest"/></param>
    /// <returns>
    /// A <see cref="Task"/> é uma operação assíncrona que retorna um <see cref="UsuarioCadastroResponse"/>
    /// ao final da operação.
    /// </returns>
    public async Task<UsuarioCadastroResponse> AtualizarPermisao(UsuarioAtualizarPermisaoRequest usuarioPermisao)
    {
        var user = await _userManager.FindByEmailAsync(usuarioPermisao.Email);

        if (user is IdentityUser)
        {
            if (!await _roleManager.RoleExistsAsync(nameof(usuarioPermisao.Roles))) 
                await _roleManager.CreateAsync(new IdentityRole(nameof(usuarioPermisao.Roles)));

            var rolesAtual = await _userManager.GetRolesAsync(user);
            if(rolesAtual is IList<string> && rolesAtual.Any())
                await _userManager.RemoveFromRolesAsync(user, rolesAtual);

            var result = await _userManager.AddToRoleAsync(user, nameof(usuarioPermisao.Roles));
            var usuarioResponse = new UsuarioCadastroResponse(result.Succeeded);

            if (!result.Succeeded && result.Errors.Count() > 0)
                usuarioResponse.AdicionarErros(result.Errors.Select(r => r.Description));

            return usuarioResponse;
        }

        var usuarioCadastroResponse = new UsuarioCadastroResponse();
        usuarioCadastroResponse.AdicionarErro($"Usuário com e-mail {usuarioPermisao.Email}, não foi encontrado.");

        return usuarioCadastroResponse;
    }

    /// <summary>
    /// Cadastra um novo usuário.
    /// </summary>
    /// <param name="usuarioCadastro">Fornecer um objeto do tipo <see cref="UsuarioCadastroRequest"/></param>
    /// <returns>
    /// A <see cref="Task"/> é uma operação assíncrona que retorna um <see cref="UsuarioCadastroResponse"/>
    /// ao final da operação.
    /// </returns>
    public async Task<UsuarioCadastroResponse> CadastrarUsuario(UsuarioCadastroRequest usuarioCadastro)
    {
        var identityUser = new IdentityUser
        {
            UserName = usuarioCadastro.Email,
            Email = usuarioCadastro.Email,
            EmailConfirmed = true
        };

        var result = await _userManager.CreateAsync(identityUser, usuarioCadastro.Senha);
        if (result.Succeeded)
            await _userManager.SetLockoutEnabledAsync(identityUser, false);

        var usuarioCadastroResponse = new UsuarioCadastroResponse(result.Succeeded);
        if (!result.Succeeded && result.Errors.Count() > 0)
            usuarioCadastroResponse.AdicionarErros(result.Errors.Select(r => r.Description));

        return usuarioCadastroResponse;
    }

    /// <summary>
    /// Método para autenticação do usuário.
    /// </summary>
    /// <param name="usuarioLogin">Fornecer um objeto do tipo <see cref="UsuarioLoginRequest"/></param>
    /// <returns>
    /// A <see cref="Task"/> é uma operação assíncrona que retorna um <see cref="UsuarioLoginResponse"/>
    /// ao final da operação.
    /// </returns>
    public async Task<UsuarioLoginResponse> Login(UsuarioLoginRequest usuarioLogin)
    {
        var result = await _signInManager.PasswordSignInAsync(usuarioLogin.Email, usuarioLogin.Senha, false, true);
        if (result.Succeeded)
            return await GerarCredenciais(usuarioLogin.Email);

        var usuarioLoginResponse = new UsuarioLoginResponse();
        if (!result.Succeeded)
        {
            if (result.IsLockedOut)
                usuarioLoginResponse.AdicionarErro("Essa conta está bloqueada");
            else if (result.IsNotAllowed)
                usuarioLoginResponse.AdicionarErro("Essa conta não tem permissão para fazer login");
            else if (result.RequiresTwoFactor)
                usuarioLoginResponse.AdicionarErro("É necessário confirmar o login no seu segundo fator de autenticação");
            else
                usuarioLoginResponse.AdicionarErro("Usuário ou senha estão incorretos");
        }

        return usuarioLoginResponse;
    }

    /// <summary>
    /// Método para obter todos os usuário cadastrados.
    /// </summary>
    /// <returns>
    /// A <see cref="Task"/> é uma operação assícrona que retorna um <see cref="UsuariosResponse"/>
    /// ao final da operação.
    /// </returns>
    public async Task<UsuariosResponse> ObterTodosUsuarios()
    {
        var result = await _userManager.Users.AsNoTracking().ToListAsync();        
        var usuariosResponse = new UsuariosResponse();
        
        if (result is List<IdentityUser>)
        {
            result.ForEach(user =>
            {
                usuariosResponse.AdicionarUsuario(user.Email, user.EmailConfirmed);
            });

            return usuariosResponse;
        }

        usuariosResponse.AdicionarErro("Não foi encontrado usuários cadastrado.");
        return usuariosResponse;
    }

    /// <summary>
    /// Método para gerar as credencias do usuário.
    /// </summary>
    /// <param name="email">Fornecer o e-mail do usuário.</param>
    /// <returns>
    /// A <see cref="Task"/> é uma operação assíncrona que retorna um <see cref="UsuarioLoginResponse"/>
    /// ao final da operação.
    /// </returns>
    private async Task<UsuarioLoginResponse> GerarCredenciais(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        var accessTokenClaims = await ObterClaims(user, adicionarClaimsUsuario: true);
        var refreshTokenClaims = await ObterClaims(user, adicionarClaimsUsuario: false);

        var dataExpiracaoAccessToken = DateTime.Now.AddSeconds(_jwtOptions.AccessTokenExpiration);
        var dataExpiracaoRefreshToken = DateTime.Now.AddSeconds(_jwtOptions.RefreshTokenExpiration);

        var accessToken = GerarToken(accessTokenClaims, dataExpiracaoAccessToken);
        var refreshToken = GerarToken(refreshTokenClaims, dataExpiracaoRefreshToken);

        return new UsuarioLoginResponse
        (
            sucesso: true,
            accessToken: accessToken,
            refreshToken: refreshToken
        );
    }

    /// <summary>
    /// Método para gerar token.
    /// </summary>
    /// <param name="claims">Fornecer as politicas que se aplicaram ao usuário.</param>
    /// <param name="dataExpiracao">Fornecer o periodo de validade do token.</param>
    /// <returns>
    /// O método retornar uma <see cref="string"/> com o token.
    /// </returns>
    private string GerarToken(IEnumerable<Claim> claims, DateTime dataExpiracao)
    {
        var jwt = new JwtSecurityToken(
            issuer: _jwtOptions.Issuer,
            audience: _jwtOptions.Audience,
            claims: claims,
            notBefore: DateTime.Now,
            expires: dataExpiracao,
            signingCredentials: _jwtOptions.SigningCredentials);

        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }

    /// <summary>
    /// Método para obter as politicas de usuário.
    /// </summary>
    /// <param name="user">Fornecer um usuário do tipo <see cref="IdentityUser"/></param>
    /// <param name="adicionarClaimsUsuario">Se <see cref="true"/> pega todas as politicas cadastrada na base de dados, se não aplica apenas as politicas padrão.</param>
    /// <returns>
    /// A <see cref="Task"/> é uma operação assíncrona que retorna uma <see cref="IList"/> de <see cref="Claim"/>
    /// ao final da operação.
    /// </returns>
    private async Task<IList<Claim>> ObterClaims(IdentityUser user, bool adicionarClaimsUsuario)
    {
        var claims = new List<Claim>();

        claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
        claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
        claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, DateTime.Now.ToString()));
        claims.Add(new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToString()));

        if (adicionarClaimsUsuario)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);

            claims.AddRange(userClaims);

            foreach (var role in roles)
                claims.Add(new Claim("role", role));
        }

        return claims;
    }
}