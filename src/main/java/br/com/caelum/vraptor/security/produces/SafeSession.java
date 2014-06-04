package br.com.caelum.vraptor.security.produces;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;

import javax.enterprise.inject.Vetoed;

import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;

@Vetoed
public class SafeSession implements Session, Serializable {

	private Session session;

	public SafeSession(Session session) {
		this.session = session;
	}

	@Override
	public Serializable getId() {
		return session.getId();
	}

	@Override
	public Date getStartTimestamp() {
		return session.getStartTimestamp();
	}

	@Override
	public Date getLastAccessTime() {
		return session.getLastAccessTime();
	}

	@Override
	public long getTimeout() throws InvalidSessionException {
		return session.getTimeout();
	}

	@Override
	public void setTimeout(long maxIdleTimeInMillis)
			throws InvalidSessionException {
		session.setTimeout(maxIdleTimeInMillis);
	}

	@Override
	public String getHost() {
		return session.getHost();
	}

	@Override
	public void touch() throws InvalidSessionException {
		session.touch();
	}

	@Override
	public void stop() throws InvalidSessionException {
		session.stop();
	}

	@Override
	public Collection<Object> getAttributeKeys() throws InvalidSessionException {
		return session.getAttributeKeys();
	}

	@Override
	public Object getAttribute(Object key) throws InvalidSessionException {
		return session.getAttribute(key);
	}

	@Override
	public void setAttribute(Object key, Object value)
			throws InvalidSessionException {
		session.setAttribute(key, value);
	}

	@Override
	public Object removeAttribute(Object key) throws InvalidSessionException {
		return session.removeAttribute(key);
	}

}
