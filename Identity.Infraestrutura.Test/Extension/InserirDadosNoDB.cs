using Identity.Application.DTOs.Request;
using Identity.Application.Interfaces.ServicesIdentity;

namespace Identity.Infraestrutura.Test.Extension
{
    public static class InserirDadosNoDB
    {
        public static async Task CasdastraUsuarios(this IIdentityService service)
        {

            List<UsuarioCadastroRequest> usuarioCadastroRequest = new List<UsuarioCadastroRequest>()
            {
               new UsuarioCadastroRequest
               {
                   Email = "Teste@teste.com",
                   Senha = "Ci102030a@",
                   SenhaConfirmacao = "Ci102030a@"
               },
               new UsuarioCadastroRequest
               {
                   Email = "Teste1@teste.com",
                   Senha = "Ci102030a@1",
                   SenhaConfirmacao = "Ci102030a@1"
               },

            };

            foreach (var item in usuarioCadastroRequest)
            {
                await service.CadastrarUsuario(item);
            }
        }
    }
}
