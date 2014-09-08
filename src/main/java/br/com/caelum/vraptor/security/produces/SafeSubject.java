package br.com.caelum.vraptor.security.produces;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.ExecutionException;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;

public class SafeSubject implements Serializable, Subject {
    
    private Subject subject;

    public SafeSubject(Subject subject) {
        this.subject = subject;
    }

    @Override
    public Object getPrincipal() {
        return subject.getPrincipal();
    }

    @Override
    public PrincipalCollection getPrincipals() {
        return subject.getPrincipals();
    }

    @Override
    public boolean isPermitted(String permission) {
        return subject.isPermitted(permission);
    }

    @Override
    public boolean isPermitted(Permission permission) {
        return subject.isPermitted(permission);
    }

    @Override
    public boolean[] isPermitted(String... permissions) {
        return subject.isPermitted(permissions);
    }

    @Override
    public boolean[] isPermitted(List<Permission> permissions) {
        return subject.isPermitted(permissions);
    }

    @Override
    public boolean isPermittedAll(String... permissions) {
        return subject.isPermittedAll(permissions);
    }

    @Override
    public boolean isPermittedAll(Collection<Permission> permissions) {
        return subject.isPermittedAll(permissions);
    }

    @Override
    public void checkPermission(String permission)
            throws AuthorizationException {
        this.subject.checkPermission(permission);
    }

    @Override
    public void checkPermission(Permission permission)
            throws AuthorizationException {
        this.subject.checkPermission(permission);
    }

    @Override
    public void checkPermissions(String... permissions)
            throws AuthorizationException {
        this.subject.checkPermissions(permissions);
    }

    @Override
    public void checkPermissions(Collection<Permission> permissions)
            throws AuthorizationException {
        this.subject.checkPermissions(permissions);
    }

    @Override
    public boolean hasRole(String roleIdentifier) {
        return this.subject.hasRole(roleIdentifier);
    }

    @Override
    public boolean[] hasRoles(List<String> roleIdentifiers) {
        return this.subject.hasRoles(roleIdentifiers);
    }

    @Override
    public boolean hasAllRoles(Collection<String> roleIdentifiers) {
        return this.subject.hasAllRoles(roleIdentifiers);
    }

    @Override
    public void checkRole(String roleIdentifier) throws AuthorizationException {
        this.subject.checkRole(roleIdentifier);
    }

    @Override
    public void checkRoles(Collection<String> roleIdentifiers)
            throws AuthorizationException {
        this.subject.checkRoles(roleIdentifiers);
    }

    @Override
    public void checkRoles(String... roleIdentifiers)
            throws AuthorizationException {
        this.subject.checkRoles(roleIdentifiers);
    }

    @Override
    public void login(AuthenticationToken token) throws AuthenticationException {
        this.subject.login(token);
    }

    @Override
    public boolean isAuthenticated() {
        return this.subject.isAuthenticated();
    }

    @Override
    public boolean isRemembered() {
        return this.subject.isRemembered();
    }

    @Override
    public Session getSession() {
        return this.subject.getSession();
    }

    @Override
    public Session getSession(boolean create) {
        return this.subject.getSession(create);
    }

    @Override
    public void logout() {
        this.subject.logout();
    }

    @Override
    public <V> V execute(Callable<V> callable) throws ExecutionException {
        return this.subject.execute(callable);
    }

    @Override
    public void execute(Runnable runnable) {
        this.subject.execute(runnable);
    }

    @Override
    public <V> Callable<V> associateWith(Callable<V> callable) {
        return this.subject.associateWith(callable);
    }

    @Override
    public Runnable associateWith(Runnable runnable) {
        return this.subject.associateWith(runnable);
    }

    @Override
    public void runAs(PrincipalCollection principals)
            throws NullPointerException, IllegalStateException {
        this.subject.runAs(principals);
    }

    @Override
    public boolean isRunAs() {
        return this.subject.isRunAs();
    }

    @Override
    public PrincipalCollection getPreviousPrincipals() {
        return this.subject.getPreviousPrincipals();
    }

    @Override
    public PrincipalCollection releaseRunAs() {
        return this.subject.releaseRunAs();
    }
}
