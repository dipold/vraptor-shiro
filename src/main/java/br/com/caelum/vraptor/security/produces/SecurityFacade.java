package br.com.caelum.vraptor.security.produces;

import java.util.Arrays;

import javax.annotation.PostConstruct;
import javax.enterprise.inject.Any;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationListener;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.authc.credential.PasswordMatcher;
import org.apache.shiro.authc.credential.PasswordService;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.com.caelum.vraptor.security.realm.CustomAuthorizingRealm;

import com.google.common.collect.Iterables;

@Singleton 
public class SecurityFacade {

	@Inject private CustomAuthorizingRealm realm;
	@Inject @Any private Instance<AuthenticationListener> authenticationListeners;
	
	private static final Logger log = LoggerFactory.getLogger(SecurityFacade.class);
	
	@PostConstruct
	public void init() {
		log.info("Initializing Shiro SecurityManager");
		
		//TODO: Tornar a criptografia dos passwords opcional
		realm.setCredentialsMatcher(new PasswordMatcher());
		
		ModularRealmAuthenticator authenticator = new ModularRealmAuthenticator();
		authenticator.setAuthenticationListeners(Arrays.asList(Iterables.toArray(authenticationListeners, AuthenticationListener.class)));
		authenticator.setRealms(Arrays.asList((Realm)realm));

//		DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager(realm);
		DefaultSecurityManager securityManager = new DefaultSecurityManager(realm);
		securityManager.setAuthenticator(authenticator);
		
		SecurityUtils.setSecurityManager(securityManager);
	}

	@Produces
	public SecurityManager getSecurityManager() {
		return SecurityUtils.getSecurityManager();
	}

	@Produces
	public Subject getSubject() {
		return SecurityUtils.getSubject();
	}

	@Produces
	public Session getSession() {
		return SecurityUtils.getSubject().getSession();
	}

	@Produces
	public PasswordService getPasswordService() {
		return new DefaultPasswordService();
	}
}
