using System.ComponentModel.DataAnnotations;
using Identity.Application.Enums;

namespace Identity.Application.DTOs.Request;

public class UsuarioAtualizarPermisaoRequest
{
    [Required(ErrorMessage = "O campo {0} é obrigatório")]
    [EmailAddress(ErrorMessage = "O campo {0} é inválido")]
    public string Email { get; set; }

    [Required(ErrorMessage = "O campo {0} é obrigatório")]
    public Roles Roles { get; set; }

}
