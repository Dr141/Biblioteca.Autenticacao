namespace Identity.Infraestrutura.Test.Interface;
public interface IIdentityServiceTest
{
    Task CadastrarUsuarioTest();
    Task LoginTest();
    Task AtualizarPermisaoTest();
    Task AtualizarSenhaTest();
    Task AtualizarSenhaInternoTest();
    Task ObterTodosUsuariosTest();
}