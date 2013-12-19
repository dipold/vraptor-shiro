package br.com.caelum.vraptor.security.realm;

import java.util.Set;

import javax.inject.Inject;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import br.com.caelum.vraptor.security.User;
import br.com.caelum.vraptor.security.Permission;

public class CustomAuthorizingRealm extends AuthorizingRealm {
	
	@Inject private Permission permission;
	
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		UsernamePasswordToken upToken = (UsernamePasswordToken)token;
		User user = permission.getUserByUsername(upToken.getUsername());
		if (user == null) {
            throw new AuthenticationException();
        }
		return new SimpleAuthenticationInfo(user, user.getHashedPassword(), getName());
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		User user = (User) getAvailablePrincipal(principals);

		Set<String> roles = permission.getRolesByUser(user.getUsername());
		SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo(roles);

		for (String role : roles) {
			Set<String> permissions = permission.getPermissionsByRole(role);
			simpleAuthorizationInfo.addStringPermissions(permissions);
		}

        return simpleAuthorizationInfo;		
	}
}
