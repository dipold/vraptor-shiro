package br.com.caelum.vraptor.security.strategy;

import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;

public interface ShiroInitConfigStrategy {

	void init(DefaultWebSecurityManager securityManager, AuthorizingRealm realm);
}
