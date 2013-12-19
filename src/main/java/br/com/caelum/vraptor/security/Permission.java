package br.com.caelum.vraptor.security;

import java.util.Set;

public interface Permission {
	User getUserByUsername(String username);
	Set<String> getRolesByUser(String user);
	Set<String> getPermissionsByRole(String role);
}
