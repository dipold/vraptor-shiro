package br.com.caelum.vraptor.security;

public class User {

	private String username;
	private String hashedPassword;

	public User() {}

	public User(String username, String hashedPassword) {
		this.username = username;
		this.hashedPassword = hashedPassword;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getHashedPassword() {
		return hashedPassword;
	}

	public void setHashedPassword(String hashedPassword) {
		this.hashedPassword = hashedPassword;
	}
}
