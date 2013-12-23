package br.com.caelum.vraptor.security;

import java.io.Serializable;

public class User implements Serializable {

	private static final long serialVersionUID = 984641961658723523L;
	
	private String username;
	private String password;

	public User() {}

	public User(String username, String password) {
		this.username = username;
		this.password = password;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}
