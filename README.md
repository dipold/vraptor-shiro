# VRaptor Apache Shiro Plugin

VRaptor Apache Shiro Plugin provides support to security authentication, authorization, cryptography and session management by Apache Shiro.

## Exemplos

### Configuração Básica/Obrigatória

A configuração básica/obrigatória exige que sejam implementados as seguintes interfaces:

* <code>RestrictionsListener</code>

	A implementação dessa interface deve ser feita em seu <code>@Controller</code> e serve para que você decida o destino do seu usuário caso ele se confronte com um problema de autenticação ou autorização. Exemplo:

```java
@Controller
public class AuthController implements RestrictionsListener {
	@Override
	public void onUnauthenticatedRestriction(UnauthenticatedException e) {
		result.include("error", e.toString());
		result.forwardTo(LoginController.class).formLogin();
		//OR
		result.use(Results.status()).forbidden(e.toString());		
	}
	@Override
	public void onUnauthorizedRestriction(UnauthorizedException e) {
		result.include("error", e.toString());
		result.forwardTo(LoginController.class).accessDeniedPage();
		//OR
		result.use(Results.status()).forbidden(e.toString());		
	}
}
```
    
* <code>Permission</code>

	A implementação dessa interface serve para fazer a ponte entre os dados dos usuários que estão disponíveis em seu banco de dados, arquivo.ini, etc. para o plugin.
  
```java
public class AuthService implements Permission {

	@Inject UsuarioDAO usuarioDAO;
	
	@Override
	public User getUserByUsername(String username) {
		Usuario usuario = usuarioDAO.selecionarUsuarioByUsername(username);
		return new User(usuario.getUsername(), usuario.getPassword());
	}
 
	@Override
	public Set<String> getRolesByUser(String username) {
		return usuarioDAO.listarPerfilsByUsername(username);
	}

	@Override
	public Set<String> getPermissionsByRole(String role) {
		return usuarioDAO.listarPermissoesByPerfil(role);
	}
}
```

* <code>AuthenticationListener</code> (Opcional)

	A implementação dessa interface é opcional e serve para observar quando um usuário logar ou deslogar da sessão.

### Considerações

É necessário criptografar as senhas do usuário, para isso o plugin fornece a interface <code>PasswordService</code> que tem como objetivo único fornecer uma interface simples para criptografia.

Exemplo:

```java
@Controller
public class UsuarioDAO {
	@Inject UsuarioDAO usuarioDAO;
	@Inject PasswordService passwordService;
	
	public void salvarUsuario(String username, String plainTextPassword) {
		usuarioDAO.salvarNovoUsuario(username, passwordService.encryptPassword(plainTextPassword));
	}
}
```
 
Para fazer o login das credenciais do usuário você pode usar a interface <code>Subject</code> que em uma definição simplória representa o usuário corrente.

Caso seja necessário "salvar" mais dados em sessão, o plugin também fornece a interface <code>Session</code>.
Exemplo:

```java
@Controller
public class UsuarioDAO {
	@Inject Subject currentUser;
	@Inject Session session;
	
	@Post("/login")
	public void login(String username, String plainTextPassword, boolean remember) {
		try {
			currentUser.login(new UsernamePasswordToken(username, plainTextPassword, remember));
			session.setAttribute(key, value);
		} 
		catch (UnknownAccountException e) {} 
		catch (IncorrectCredentialsException e) {}
		catch (LockedAccountException e) {}
		catch (ExcessiveAttemptsException e) {}
		catch (AuthenticationException e) {}		
	}
	
	@Get("/logout")
	public void logout() {
		currentUser.logout();
	}
}
```

### Configuração/Uso via Anotações

A anotação <code>@Secured</code> tem a função de "marcar" o elemento para ser observado pelo plugin.  
Ela pode ser usada tanto a nível de classe:

```java
@Secured
public class SecuredClass {
	@RequiresUser			public boolean requiresUserLoggedIn() {}
	@RequiresAuthentication	public boolean requiresAuthentication() {}
}
```
  
Quanto de método:
  
```java
public class SecuredClass {
	public boolean bazingaMethod() {}
	@Secured @RequiresAuthentication public boolean requiresAuthentication() {}
}
```

Para tornar um elemento seguro, em conjunto com a anotação <code>@Secured</code>, deve ser usado uma das seguintes anotações:

1. Para autenticação:

	<code>@RequiresUser</code>
	Onde o "subject" é definido como o usuário corrente que teve suas credenciais autenticadas ou lembradas em momento ou sessão anterior. 
	
	<code>@RequiresAuthentication</code>
	Onde o "subject" é definido como o usuário corrente que possui suas credenciais autenticadas na sessão atual.
      
	<code>@RequiresGuest</code>
	Onde o "subject" é definido como o usuário corrente que não possui suas credenciais autenticadas em nenhum momento (usuário anônimo).
      
2. Para autorização:

	<code>@RequiresRoles</code>
	Define que apenas o usuário autenticado e pertencente a determinado perfil (role) possa executar 
      
	<code>@RequiresPermissions</code>
	Define que apenas o usuário autenticado e com determinada permissão possa executar. As permissções são definidas por uma string e pode ser usada em conjunto com o coringa * para designar acesso universal.
      
	Exemplos:
	
		printer:hp1100:view

		printer:hp1100:manage
		
		printer:hp1100:print
		
		printer:lp7200:view
		
		printer:lp7200:manage
		
		printer:lp7200:print
		
	E um perfil(role) pode possuir permissões de:
	
		printer:*
		
		printer:*:view
		
		printer:hp1100:*
		
		printer:hp1100:manage      

As anotações de autenticação ou de autorização podem ser usadas a nível de método, de classe, de super classe ou de interface.
Exemplo: 

```java
@Secured
public class SecuredClass {
	@RequiresUser			public boolean requiresUser() {}
	@RequiresAuthentication	public boolean requiresAuthentication() {}
	@RequiresGuest			public boolean requiresGuest() {}

	@RequiresRoles("User")				public boolean requiresRoleUser() {}
	@RequiresRoles("Admin")				public boolean requiresRoleAdmin() {}
	@RequiresRoles({"User","Admin"})	public boolean requiresRoleUserAndAdmin() {}

	@RequiresPermissions("doc:read")				public boolean requiresPermissionReadDoc() {}
	@RequiresPermissions("doc:write")				public boolean requiresPermissionWriteDoc() {}
	@RequiresPermissions({"doc:read","doc:write"})	public boolean requiresPermissionReadWriteDoc() {}
}
```

### Programaticamente

É possível a configuração/uso do plugin sem anotações, o que permite maior controle/dinamismo em seu projeto.
Exemplo:

```java
public class SecuredClass {
	@Inject private Subject currentUser;
	
	public boolean requiresAuthentication() { if (currentUser.isAuthenticated()) {...} }
        
	public boolean requiresRoleUser() { if (currentUser.hasRole("User")) {...} }
	public boolean requiresRoleAdmin() { if (currentUser.hasRole("Admin")) {...} }
	public boolean requiresRoleUserAndAdmin() { if (currentUser.hasRoles(Arrays.AsList("User", "Admin"))) {...} }
        
	public boolean requiresPermissionReadDoc() { if (currentUser.isPermitted("doc:read")) {...} }
	public boolean requiresPermissionWriteDoc() { if (currentUser.isPermitted("doc:write")) {...} }
	public boolean requiresPermissionReadWriteDoc() { if (currentUser.isPermittedAll(Arrays.AsList("doc:read", "doc:write"))) {...} }
}
```
