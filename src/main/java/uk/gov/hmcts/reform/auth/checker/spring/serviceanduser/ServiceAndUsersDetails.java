package uk.gov.hmcts.reform.auth.checker.spring.serviceanduser;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

public class ServiceAndUsersDetails extends ServiceAndUserDetails {

    private final org.springframework.security.core.userdetails.User authorizedUser;

    public ServiceAndUsersDetails(String username, String token, Collection<String> authorities, String servicename) {
    	super(username, token, authorities, servicename);
    	this.authorizedUser = this;
    }

    public ServiceAndUsersDetails(String username, String token, Collection<String> authorities, String servicename, String authorizedUsername, Collection<String> authorizedAuthorities) {
        super(username, token, authorities, servicename);
        this.authorizedUser = new org.springframework.security.core.userdetails.User(authorizedUsername, token, toGrantedAuthorities(authorizedAuthorities));
    }

    public String getAuthorizedUsername()
    {
    	return authorizedUser.getUsername();
    }

    public Collection<GrantedAuthority> getAuthorizedAuthorities()
    {
    	return this.authorizedUser.getAuthorities();
    }

    public String getEffectiveUsername()
    {
    	return getUsername();
    }

    public Collection<GrantedAuthority> getEffectiveAuthorities()
    {
    	return getAuthorities();
    }
}
