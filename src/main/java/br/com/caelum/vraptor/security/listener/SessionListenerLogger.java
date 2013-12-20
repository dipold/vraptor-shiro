package br.com.caelum.vraptor.security.listener;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SessionListenerLogger implements SessionListener {

	private static final Logger log = LoggerFactory.getLogger(SessionListenerLogger.class);
	
	@Override
	public void onStart(Session session) {
		log.info("Session started for [{}]", session.getId());		
	}

	@Override
	public void onStop(Session session) {
		log.info("Session stoped for [{}]", session.getId());		
	}

	@Override
	public void onExpiration(Session session) {
		log.info("Session espirated for [{}]", session.getId());		
	}
}
