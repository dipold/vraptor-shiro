# VRaptor Apache Shiro Plugin

VRaptor Apache Shiro Plugin provides support to security authentication, authorization, cryptography and session management by Apache Shiro.

## Exemplos

### Configuração Básica/Obrigatória

A configuração básica/obrigatória exige que sejam implementados as seguintes interfaces:

* <code>AuthorizationRestrictionListener</code>

	A implementação dessa interface deve ser feita em seu <code>@Controller</code> e serve para que você decida o destino do seu usuário caso ele se confronte com um problema de autenticação ou autorização. Exemplo:

```java
@Controller
public class AuthController implements RestrictionsListener {
	@Inject private Result result;
	
	@Override
	public void onAuthorizationRestriction(AuthorizationException e) {
		result.include("error", e.toString());
		result.forwardTo(LoginController.class).formLogin();
		//OR
		result.use(Results.status()).forbidden(e.toString());		
	}
}
```
    
* <code>Permission</code>

	A implementação dessa interface serve para fazer a ponte entre os dados dos usuários que estão disponíveis em seu banco de dados, arquivo.ini, etc. para o plugin. Exemplo:
  
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

* <code>SessionListener</code> (Opcional)

	A implementação dessa interface é opcional e serve para observar quando a sessão de um usuário inicia, finaliza ou expira.

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
	public boolean publicMethod() {}
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
	Define que apenas o usuário autenticado e com determinada permissão possa executar. As permissões são definidas por uma string e pode ser usada em conjunto com o coringa * para designar acesso universal.
      
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

As anotações de autenticação ou de autorização podem ser usadas a nível de método ou de classe.
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

## Tags JSP/JSTL

Apache Shiro provê o uso de tags JSP ou JSTL para gerenciar o conteúdo de suas páginas baseado no estado do usuário corrente.

### Configuração

Para usar qualquer uma das tags existentes, adicione a Tag Library Descriptor (TDL) abaixo no cabeçalho de seu arquivo JSP:

```jsp
<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>
```

### Uso

#### Guest Tag

A tag <code>guest</code> irá mostrar o conteúdo envolto apenas se o atual usuário não estiver logado (usuário anônimo). Exemplo:

```jsp
<shiro:guest>
	Olá!  Por favor <a href="/login">Acesse sua Conta</a> ou <a href="/cadastro">Cadastre-se</a> agora!
</shiro:guest>
```

#### User Tag

A tag <code>user</code> irá mostrar o conteúdo envolto caso o usuário atual tiver sido previamente logado.

```jsp
<shiro:user>
    Bem vindo João!  Você não é João? Clique <a href="/login">aqui<a> para acessar sua conta.
</shiro:user>
```

#### Authenticated e NotAuthenticated Tag

A tag <code>authenticated</code> irá mostrar o conteúdo envolto caso o usuário atual tenha se logado com sucesso durante a sessão atual. 
Essa tag é mais restritiva que a tag <code>user</code> e é logicamente oposta a tag <code>notAuthenticated</code>.

```jsp
<shiro:authenticated>
    <a href="/atualizaCadastro">Atualize as informações de seu cartão de crédito</a>.
</shiro:authenticated>

<shiro:notAuthenticated>
    Por favor, <a href="/login">Insira suas Credenciais</a> para atualizar as informações de seu cartão de crédito.
</shiro:notAuthenticated>
```

#### Principal Tag

A tag <code>principal</code> mostrar o nome do usuário atual:

```jsp
Olá, <shiro:principal property="username"/>, como vai você?
```

Essa tag é equivalente a:

```jsp
Olá, <%= SecurityUtils.getSubject().getPrincipals().oneByType(User.class).getUsername().toString() %>, como vai você?
```

#### HasRole e LacksRole Tag

A tag <code>hasRole</code> mostrará o conteúdo envolto se usuário atual é pertencente ao perfil indicado.
Essa tag é logicamente oposta a tag <code>lacksRole</code>:

```jsp
<shiro:hasRole name="admin">
    <a href="/admin">Acesso ao Administrador</a>
</shiro:hasRole>

<shiro:lacksRole name="admin">
    Lamento, mas você não tem permissão para acessar área administrativa.
</shiro:lacksRole>
```

#### HasAnyRoles Tag

A tag <code>hasAnyRoles</code> mostrará o conteúdo envolto se usuário atual é pertencente a qualquer um dos perfis indicados.

```jsp
<shiro:hasAnyRoles name="desenvolvedor, gerente de projeto, admin">
    Você é um desenvolvedor, gerente de projeto ou administrador.
</shiro:hasAnyRoles>
```

#### HasPermission e LacksPermission Tag

A tag <code>hasPermission</code> mostrará o conteúdo envolto se usuário atual é possui a permissão/habilidade especificada.
Essa tag é logicamente oposta a tag <code>lacksPermission</code>:

```jsp
<shiro:hasPermission name="user:create">
    <a href="/formUser">Cadastrar novo Usuário</a>
</shiro:hasPermission>

<shiro:lacksPermission name="user:delete">
    Lamento, mas você não possui permissão para remover contas de usuário.
</shiro:lacksPermission>

<shiro:lacksPermission name="user:*">
    Lamento, mas você não possui permissão para qualquer ação com contas de usuário
</shiro:lacksPermission>
```


