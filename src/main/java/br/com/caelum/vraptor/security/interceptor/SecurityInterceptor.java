package br.com.caelum.vraptor.security.interceptor;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;

import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.authz.aop.AnnotationsAuthorizingMethodInterceptor;
import org.apache.shiro.subject.Subject;

import br.com.caelum.vraptor.security.AuthorizationRestrictionListener;
import br.com.caelum.vraptor.security.annotation.Secured;

@Interceptor
@Secured
public class SecurityInterceptor extends AnnotationsAuthorizingMethodInterceptor {

	@Inject private AuthorizationRestrictionListener listener;
	@Inject private Subject subject;
	
	public SecurityInterceptor() { super(); }

	@AroundInvoke
	public Object check(InvocationContext ctx) throws Exception {
		try {
			System.out.println("Starting vraptor-shiro security validation.");
			Class<?> c = ctx.getTarget().getClass();
	        Method m = ctx.getMethod();

	        if (!subject.isAuthenticated() && hasAnnotation(c, m, RequiresAuthentication.class)) {
	            throw new AuthorizationException("Authentication required");
	        }

	        if (subject.getPrincipal() != null && hasAnnotation(c, m, RequiresGuest.class)) {
	            throw new AuthorizationException("Guest required");
	        }

	        if (subject.getPrincipal() == null && hasAnnotation(c, m, RequiresUser.class)) {
	            throw new AuthorizationException("User required");
	        }

	        RequiresRoles roles = getAnnotation(c, m, RequiresRoles.class);

	        if (roles != null) {
	            subject.checkRoles(Arrays.asList(roles.value()));
	        }

	        RequiresPermissions permissions = getAnnotation(c, m, RequiresPermissions.class);

	        if (permissions != null) {
	             subject.checkPermissions(permissions.value());
	        }
	        return ctx.proceed();
		} catch(AuthorizationException e) {
			listener.onAuthorizationRestriction(e);
		}
		return null;
	}
	
	private static boolean hasAnnotation(Class<?> c, Method m, Class<? extends Annotation> a) {
        return m.isAnnotationPresent(a)
            || c.isAnnotationPresent(a)
            || c.getSuperclass().isAnnotationPresent(a);
    }

    private static <A extends Annotation> A getAnnotation(Class<?> c, Method m, Class<A> a) {
        return m.isAnnotationPresent(a) ? m.getAnnotation(a)
            : c.isAnnotationPresent(a) ? c.getAnnotation(a)
            : c.getSuperclass().getAnnotation(a);
    }
}
