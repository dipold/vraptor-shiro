package br.com.caelum.vraptor.security;

import org.apache.shiro.authz.AuthorizationException;

public interface AuthorizationRestrictionListener {

	void onAuthorizationRestriction(AuthorizationException e);
}
