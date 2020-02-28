package uk.gov.hmcts.reform.auth.checker.spring.serviceanduser;

import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import lombok.extern.slf4j.Slf4j;
import uk.gov.hmcts.reform.auth.checker.core.RequestAuthorizer;
import uk.gov.hmcts.reform.auth.checker.core.exceptions.AuthCheckerException;
import uk.gov.hmcts.reform.auth.checker.core.service.Service;
import uk.gov.hmcts.reform.auth.checker.core.user.User;
import uk.gov.hmcts.reform.auth.checker.core.user.UserRequestAuthorizer;


@Slf4j
public class AuthCheckerServiceAndUserFilter extends AbstractPreAuthenticatedProcessingFilter {

    private final RequestAuthorizer<Service> serviceRequestAuthorizer;
    private final RequestAuthorizer<User> userRequestAuthorizer;

    public AuthCheckerServiceAndUserFilter(RequestAuthorizer<Service> serviceRequestAuthorizer,
                                           RequestAuthorizer<User> userRequestAuthorizer) {
        this.serviceRequestAuthorizer = serviceRequestAuthorizer;
        this.userRequestAuthorizer = userRequestAuthorizer;
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        Service service = authorizeService(request);
        if (service == null) {
            return null;
        }

        return authorizeUser(request, service);
//
//        User user = authorizeUser(request)[0];
//        if (user == null) {
//            return null;
//        }
//
//        return new ServiceAndUserPair(service, authorizedUser, effectiveUser);
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return request.getHeader(UserRequestAuthorizer.AUTHORISATION);
    }

    private ServiceAndUsers authorizeUser(HttpServletRequest request, Service service) {
        try {
        	User authorizedUser = userRequestAuthorizer.authorise(request);
        	if (authorizedUser == null)
        	{
        		return null;
        	}
        	User effectiveUser = authorizeEffectiveUser(request, authorizedUser);
            return new ServiceAndUsers(service, authorizedUser, effectiveUser);
        } catch (AuthCheckerException e) {
            log.warn("Unsuccessful user authentication", e);
            return null;
        }
    }

    private User authorizeEffectiveUser(HttpServletRequest request, User authorizedUser)
    {
    	User effectiveUser = authorizedUser;
    	if (authorizedUser.getRoles().contains("sys_ccd_data_store_api_as_user"))
    	{
    		String effectiveUserHeader = request.getHeader("EffectiveUser");
	    	String[] effectiveUserDetails = effectiveUserHeader.split(",");
	    	if (effectiveUserHeader != null && effectiveUserHeader.trim().length() > 0)
	    	{
		    	String effectiveUserId = effectiveUserDetails[0].trim();
		    	Set<String> effectiveUserRoles = new HashSet<>();
		    	for (int i = 1; i < effectiveUserDetails.length; ++i)
		    	{
		    		effectiveUserRoles.add(effectiveUserDetails[i].trim());
		    	}
		    	effectiveUser = new User(effectiveUserId, effectiveUserRoles);
	    	}
    	}
    	return effectiveUser;
    }

    private Service authorizeService(HttpServletRequest request) {
        try {
            return serviceRequestAuthorizer.authorise(request);
        } catch (AuthCheckerException e) {
            log.warn("Unsuccessful service authentication", e);
            return null;
        }
    }

}
