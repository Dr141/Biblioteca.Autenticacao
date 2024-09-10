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
- Configurar a base de dados
  -      services.AddDbContext<IdentityDataContext>(options =>
               options.UseNpgsql(configuration.GetConnectionString("Connection")));
- Configurar o Ef para o Identity 
  -      services.AddDefaultIdentity<IdentityUser>()
                 .AddRoles<IdentityRole>()
                 .AddEntityFrameworkStores<IdentityDataContext>()
                 .AddDefaultTokenProviders();.
- Registra a dependencia `services.AddScoped<IIdentityService, IdentityService>();`.
- Executar o comando `Add-Migration Inicial_Identity -context IdentityDataContext` para criar a migração inicial.
- Exemplo de configuração da autenticação Identity e Jwt
  -         var jwtAppSettingOptions = configuration.GetSection(nameof(JwtOptions));
            var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(configuration.GetSection("JwtOptions:SecurityKey").Value));

            services.Configure<JwtOptions>(options =>
            {
                options.Issuer = jwtAppSettingOptions[nameof(JwtOptions.Issuer)];
                options.Audience = jwtAppSettingOptions[nameof(JwtOptions.Audience)];
                options.SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512);
                options.AccessTokenExpiration = int.Parse(jwtAppSettingOptions[nameof(JwtOptions.AccessTokenExpiration)] ?? "0");
                options.RefreshTokenExpiration = int.Parse(jwtAppSettingOptions[nameof(JwtOptions.RefreshTokenExpiration)] ?? "0");
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
                ValidIssuer = configuration.GetSection("JwtOptions:Issuer").Value,

                ValidateAudience = true,
                ValidAudience = configuration.GetSection("JwtOptions:Audience").Value,

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
       
            services.AddSingleton<IAuthorizationHandler, HorarioComercialHandler>();
            services.AddAuthorization(options =>
            {
                options.AddPolicy(Policies.HorarioComercial, policy =>
                    policy.Requirements.Add(new HorarioComercialRequirement()));
            });
- Exemplo de configuração no Swagger
   -        services.AddEndpointsApiExplorer();
            services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "Web consultorio API",
                    Version = "v1"
                });

                options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = @"JWT Authorization header using the Bearer scheme. 
                                Enter 'Bearer' [space] and then your token in the text input below. 
                                Example: 'Bearer 12345abcdef'",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
                });

                options.AddSecurityRequirement(new OpenApiSecurityRequirement()
                {  
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            },
                            Scheme = "oauth2",
                            Name = "Bearer",
                            In = ParameterLocation.Header,

                        },
                        new List<string>()
                    }
                });
            });
  - Também é necessário acrescentar o `app.UseAuthentication();` no arquivo de inicialização do serviço.
