# Biblioteca de autenticacação com Identity
### Objetivo
- Facilitar o desenvolvimento de projetos que necessitam de autenticação.
### Metodos
- **CadastrarUsuario:** Realiza o cadastro do usuário.
- **Login:** Realiza o login do usuário, e retorna o token de autenticação.
- **AtualizarPermisao:** Adiciona permissão ao usuário.
- **AtualizarSenha:** Atualiza a senha do usuário logado.
- **AtualizarSenhaInterno:** Atualiza a senha de outro usuário.
### Como usar
- Referenciar dll ou importar projetos na solução.
- Configurar a base de dados `services.AddDbContext<IdentityDataContext>(options =>
                options.UseNpgsql(configuration.GetConnectionString("Connection"))
            );`.
- Configurar o Ef para o Identity `services.AddDefaultIdentity<IdentityUser>()
                .AddRoles<IdentityRole>()
                .AddEntityFrameworkStores<IdentityDataContext>()
                .AddDefaultTokenProviders();`.
- Registra a dependencia `services.AddScoped<IIdentityService, IdentityService>();`.
- Executar o comando `Add-Migration Inicial_Identity -context IdentityDataContext` para criar a migração inicial.
