using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
namespace Identity.Infraestrutura.Context;

/// <summary>
/// Classe de configuração do contexto
/// </summary>
public class IdentityDataContext : IdentityDbContext
{
    /// <summary>
    /// Construtor da classe <see cref="IdentityDataContext"/>
    /// </summary>
    /// <param name="options"></param>
    public IdentityDataContext(DbContextOptions<IdentityDataContext> options) : base(options) { }

    /// <summary>
    /// Configuração para padronizar os nomes case em base de dados PostgreSql
    /// </summary>
    /// <param name="optionsBuilder"></param>
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    => optionsBuilder.UseSnakeCaseNamingConvention();
}