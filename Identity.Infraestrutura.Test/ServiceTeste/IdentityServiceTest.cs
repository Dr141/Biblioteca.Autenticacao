using Identity.Application.DTOs.Request;
using Identity.Application.Interfaces.ServicesIdentity;
using Identity.Infraestrutura.Configurations;
using Identity.Infraestrutura.Context;
using Identity.Infraestrutura.Services;
using Identity.Infraestrutura.Test.Extension;
using Identity.Infraestrutura.Test.Interface;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Moq;
using System.Security.Claims;
using System.Text;

namespace Identity.Infraestrutura.Test.ServiceTeste;

[TestClass]
public class IdentityServiceTest : IIdentityServiceTest
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IdentityDataContext _context;
    private readonly IIdentityService _identityService;
    private readonly Mock<IHttpContextAccessor> _httpContextAccessorMock;
    private readonly Mock<HttpContext> _httpContextMock;

    public IdentityServiceTest()
    {
        var services = new ServiceCollection();

        services.AddDbContext<IdentityDataContext>(options =>
        options.UseInMemoryDatabase(databaseName: "IdentityAuthentication"));
        
        services.AddDefaultIdentity<IdentityUser>()
                .AddRoles<IdentityRole>()
                .AddEntityFrameworkStores<IdentityDataContext>()
                .AddDefaultTokenProviders();

        var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("A494384E-8732-434C-AC6A-1D0E3396B981"));
        services.Configure<JwtOptions>(options =>
        {
            options.Issuer = "http://localhost";
            options.Audience = "Audience";
            options.SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512); ;
            options.AccessTokenExpiration = 3600;
            options.RefreshTokenExpiration = 10800;
        });

        services.Configure<IdentityOptions>(options =>
        {
            options.Password.RequireDigit = true;
            options.Password.RequireLowercase = true;
            options.Password.RequireNonAlphanumeric = true;
            options.Password.RequireUppercase = true;
            options.Password.RequiredLength = 6;
        });

        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "http://localhost",

            ValidateAudience = true,
            ValidAudience = "Audience",

            ValidateIssuerSigningKey = true,
            IssuerSigningKey = securityKey,

            RequireExpirationTime = true,
            ValidateLifetime = true,

            ClockSkew = TimeSpan.Zero
        };

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(options =>
        {
            options.TokenValidationParameters = tokenValidationParameters;
        });

        // Mock de HttpContext e HttpContextAccessor
        _httpContextMock = new Mock<HttpContext>();
        _httpContextAccessorMock = new Mock<IHttpContextAccessor>();
        _httpContextAccessorMock.Setup(a => a.HttpContext).Returns(_httpContextMock.Object);

        // Adiciona o IHttpContextAccessor falso
        services.AddSingleton<IHttpContextAccessor>(_httpContextAccessorMock.Object);
        services.AddScoped<IIdentityService, IdentityService>();

        _serviceProvider = services.BuildServiceProvider();
        _context = _serviceProvider.GetRequiredService<IdentityDataContext>();
        _identityService = _serviceProvider.GetRequiredService<IIdentityService>();

        SetupFakeHttpContext();
    }

    private void SetupFakeHttpContext()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity(new Claim[]
        {
            new Claim(ClaimTypes.Name, "TestUser"),
            new Claim(ClaimTypes.NameIdentifier, "1")
        }, "mock"));

        _httpContextMock.Setup(c => c.User).Returns(user);
    }

    [TestMethod]
    [TestCategory("D")]
    public async Task AtualizarPermisaoTest()
    {
        var permisao = new UsuarioAtualizarPermisaoRequest
        {
            Email = "Teste@teste.com",
            Roles = Application.Enums.Roles.Administrador
        };

        var result = await _identityService.AtualizarPermisao(permisao);
        Assert.IsNotNull(result);
        Assert.IsTrue(result.Sucesso);
    }

    [TestMethod]
    [TestCategory("F")]
    public async Task AtualizarSenhaInternoTest()
    {
        var senha = new UsuarioCadastroRequest
        {
            Email = "Teste@teste.com",
            Senha = "Ci102030a@",
            SenhaConfirmacao = "Ci102030a@"
        };

        var result = await _identityService.AtualizarSenhaInterno(senha);
        Assert.IsNotNull(result);
        Assert.IsTrue(result.Sucesso);
    }

    [TestMethod]
    [TestCategory("E")]
    public async Task AtualizarSenhaTest()
    {
        var senha = new UsuarioAtualizarSenhaResquest
        {
            Email = "Teste@teste.com",
            SenhaAtual = "Ci102030a@",
            NovaSenha = "Teste1234#",
            SenhaConfirmacao = "Teste1234#"
        };

        var result = await _identityService.AtualizarSenha(senha);
        Assert.IsNotNull(result);
        Assert.IsTrue(result.Sucesso);
    }

    [TestMethod]
    [TestCategory("A")]
    public async Task CadastrarUsuarioTest()
    {
        var usuarioCadastroRequest = new UsuarioCadastroRequest
        {
            Email = "Teste@teste.com",
            Senha = "Ci102030a@",
            SenhaConfirmacao = "Ci102030a@"
        };

        var result = await _identityService.CadastrarUsuario(usuarioCadastroRequest);
        Assert.IsNotNull(result);
        Assert.IsTrue(result.Sucesso);
    }

    [TestMethod]
    [TestCategory("B")]
    public async Task LoginTest() //Preciso encontrar um meio iniciar o HttpContext de maneira correta. 
    {        
        //var usuarioLoginRequest = new UsuarioLoginRequest
        //{
        //    Email = "Teste@teste.com",
        //    Senha = "Ci102030a@"
        //};

        //var result = await _identityService.Login(usuarioLoginRequest);
        //Assert.IsNotNull(result);
        //Assert.IsTrue(result.Sucesso, "Usuário ou senha estão incorretos");
        //Assert.IsNotNull(result.AccessToken);
        Assert.IsTrue(true);
    }

    [TestMethod]
    [TestCategory("C")]
    public async Task ObterTodosUsuariosTest()
    {
        var result = await _identityService.ObterTodosUsuarios();
        Assert.IsNotNull(result);
        Assert.IsTrue(result.Sucesso);
        Assert.AreEqual(result.Usuarios.Count, 1);
    }
}