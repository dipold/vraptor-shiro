package br.com.caelum.vraptor.security.listener;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationListener;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthenticationListenerLogger implements AuthenticationListener {
	
	private static final Logger log = LoggerFactory.getLogger(AuthenticationListenerLogger.class);

	@Override
	public void onSuccess(AuthenticationToken token, AuthenticationInfo info) {
		log.info("Login success for [{}]", token.getPrincipal());		
	}

	@Override
	public void onFailure(AuthenticationToken token, AuthenticationException ae) {
		log.info("Login failure for [{}]", token.getPrincipal());
	}

	@Override
	public void onLogout(PrincipalCollection principals) {
		log.info("Logout: [{}]", principals.getPrimaryPrincipal());		
	}
}
