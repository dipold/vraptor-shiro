package br.com.caelum.vraptor.security;

import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.UnauthorizedException;

public interface RestrictionsListener {

	void onUnauthenticatedRestriction(UnauthenticatedException e);
	void onUnauthorizedRestriction(UnauthorizedException e);
}
