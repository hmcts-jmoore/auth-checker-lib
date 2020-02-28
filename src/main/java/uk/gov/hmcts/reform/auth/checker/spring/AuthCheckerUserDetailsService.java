package uk.gov.hmcts.reform.auth.checker.spring;

import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import uk.gov.hmcts.reform.auth.checker.core.service.Service;
import uk.gov.hmcts.reform.auth.checker.core.user.User;
import uk.gov.hmcts.reform.auth.checker.spring.serviceanduser.ServiceAndUsers;
import uk.gov.hmcts.reform.auth.checker.spring.serviceanduser.ServiceAndUsersDetails;
import uk.gov.hmcts.reform.auth.checker.spring.serviceonly.ServiceDetails;
import uk.gov.hmcts.reform.auth.checker.spring.useronly.UserDetails;

public class AuthCheckerUserDetailsService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {
    @Override
    public org.springframework.security.core.userdetails.UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token) throws UsernameNotFoundException {
        Object principal = token.getPrincipal();

        if (principal instanceof Service) {
            return new ServiceDetails(((Service) principal).getPrincipal());
        }

        if (principal instanceof User) {
            User user = (User) principal;
            return new UserDetails(user.getPrincipal(), (String) token.getCredentials(), user.getRoles());
        }

        ServiceAndUsers serviceAndUsers = (ServiceAndUsers) principal;
        return new ServiceAndUsersDetails(
        		serviceAndUsers.getEffectiveUser().getPrincipal(),
        		(String) token.getCredentials(),
        		serviceAndUsers.getEffectiveUser().getRoles(),
        		serviceAndUsers.getService().getPrincipal(),
        		serviceAndUsers.getAuthorizedUser().getPrincipal(),
        		serviceAndUsers.getAuthorizedUser().getRoles());
    }
}
