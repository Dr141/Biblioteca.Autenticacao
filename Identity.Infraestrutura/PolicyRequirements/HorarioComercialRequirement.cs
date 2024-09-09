using Microsoft.AspNetCore.Authorization;

namespace Identity.Infraestrutura.PolicyRequirements;

public class HorarioComercialRequirement : IAuthorizationRequirement
{
    public HorarioComercialRequirement() { }
}