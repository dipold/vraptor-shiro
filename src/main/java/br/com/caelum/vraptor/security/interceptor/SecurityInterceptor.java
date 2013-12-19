package br.com.caelum.vraptor.security.interceptor;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;

import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.com.caelum.vraptor.security.RestrictionsListener;
import br.com.caelum.vraptor.security.annotation.Secured;

@Interceptor
@Secured
public class SecurityInterceptor {

	@Inject private Subject subject;
	@Inject private RestrictionsListener listener;

	private static final Logger log = LoggerFactory.getLogger(SecurityInterceptor.class);

	@AroundInvoke
	public Object check(InvocationContext ctx) throws Exception {
		log.debug("Declaring class: {}", ctx.getMethod().getDeclaringClass());
		log.debug("Principal is: {}", subject.getPrincipal());
		log.info("Securing {} {}", new Object[] { ctx.getMethod(), ctx.getParameters() });

		try {
			checkAuthentication(ctx.getMethod());
			checkGuest(ctx.getMethod());
			checkPermissions(ctx.getMethod());
			checkRoles(ctx.getMethod());
			checkUser(ctx.getMethod());
		} catch (UnauthenticatedException e) {
			listener.onUnauthenticatedRestriction(e);
		} catch (UnauthorizedException e) {
			listener.onUnauthorizedRestriction(e);
		}

		return ctx.proceed();
	}

	private void checkAuthentication(Method method) {
		RequiresAuthentication annotation = findAnnotation(method, RequiresAuthentication.class);
		if (annotation != null) {
			log.info("Checking if user have been authenticated during their current session");
			if (!subject.isAuthenticated()) {
				throw new UnauthenticatedException("Must have logged in during this session!");
			}	
		}
	}
	
	private void checkGuest(Method method) {
		RequiresGuest annotation = findAnnotation(method, RequiresGuest.class);
		if (annotation != null) {
			log.info("Checking if user is guest");
			if (subject.getPrincipal() != null) {
				throw new UnauthenticatedException("Only guests allowed!");
			}	
		}
	}

	private void checkPermissions(Method method) {
		RequiresPermissions annotation = findAnnotation(method, RequiresPermissions.class);
		if (annotation != null) {
			log.info("Checking permissions '{}' for user '{}'", annotation.value(), subject.getPrincipal());
			if (Logical.AND.equals(annotation.logical())) {
				subject.checkPermissions(annotation.value());
			}
			if (Logical.OR.equals(annotation.logical())) {
	            boolean hasAtLeastOnePermission = false;
	            for (String permission : annotation.value()) 
	            	if (subject.isPermitted(permission)) 
	            		hasAtLeastOnePermission = true;
	            if (!hasAtLeastOnePermission) 
	            	throw new UnauthorizedException("User does not have none of these permissions [" + annotation.value() + "]");
			}
		}
	}

	private void checkRoles(Method method) {
		RequiresRoles annotation = findAnnotation(method, RequiresRoles.class);
		if (annotation != null) {
			log.info("Checking roles '{}' for user '{}'", annotation.value(), subject.getPrincipal());
			if (Logical.AND.equals(annotation.logical())) {
				subject.checkRoles(annotation.value());
			}
			if (Logical.OR.equals(annotation.logical())) {
	            boolean hasAtLeastOneRole = false;
	            for (String role : annotation.value()) 
	            	if (subject.hasRole(role)) 
	            		hasAtLeastOneRole = true;
	            if (!hasAtLeastOneRole) 
	            	throw new UnauthorizedException("User does not have none of these roles [" + annotation.value() + "]");
			}
		}
	}

	private void checkUser(Method method) {
		RequiresUser annotation = findAnnotation(method, RequiresUser.class);
		if (annotation != null) {
			log.info("Checking user has a known identity");
			if (subject.getPrincipals() == null || subject.getPrincipals().isEmpty()) {			
				throw new UnauthenticatedException("Must be logged in");
			}
		}
	}
	
	private <A extends Annotation> A findAnnotation(Method method, Class<A> annotationClass) {
		/* Get annotation from method */
		A annotation = method.getAnnotation(annotationClass);
		
		/* Get annotation from class */
		if (annotation == null) {
			annotation = method.getDeclaringClass().getAnnotation(annotationClass);
		}
		
		/* Get annotation from interface */
		if (annotation == null) {
			for (Class<?> clazz : method.getDeclaringClass().getInterfaces()) {
				Method methodInterface;
				try {
					methodInterface = clazz.getMethod(method.getName(), method.getParameterTypes());
					findAnnotation(methodInterface, annotationClass);
				} catch (Exception e) {
					continue;
				} 
			}
		}

		/* Get annotation from super class */
		if (annotation == null) {
			if (method.getDeclaringClass().getSuperclass() != Object.class) {
				try {
					Method methodSuperClass = method.getDeclaringClass().getSuperclass().getMethod(method.getName(), method.getParameterTypes());
					findAnnotation(methodSuperClass, annotationClass);
				} catch (Exception e) {
				}
			}
		}

		return annotation;		
	}
}
