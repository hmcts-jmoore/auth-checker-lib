package uk.gov.hmcts.auth.checker.spring;


import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.function.Function;
import javax.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import uk.gov.hmcts.auth.checker.CachingSubjectResolver;
import uk.gov.hmcts.auth.checker.SubjectResolver;
import uk.gov.hmcts.auth.checker.service.Service;
import uk.gov.hmcts.auth.checker.service.ServiceRequestAuthorizer;
import uk.gov.hmcts.auth.checker.service.ServiceResolver;
import uk.gov.hmcts.auth.checker.user.User;
import uk.gov.hmcts.auth.checker.user.UserRequestAuthorizer;
import uk.gov.hmcts.auth.checker.user.UserResolver;
import uk.gov.hmcts.auth.idam.user.token.UserTokenParser;
import uk.gov.hmcts.auth.idam.service.token.ServiceTokenParser;

@Lazy
@Configuration

public class AuthCheckerConfiguration {

    @Bean
    @ConditionalOnMissingBean(name = "serviceResolver")
    public SubjectResolver<Service> serviceResolver(ServiceTokenParser serviceTokenParser, AuthCheckerProperties properties) {
        return new CachingSubjectResolver<>(new ServiceResolver(serviceTokenParser), properties.getService().getTtlInSeconds(), properties.getService().getMaximumSize());
    }

    @Bean
    @ConditionalOnMissingBean(name = "userResolver")
    public SubjectResolver<User> userResolver(UserTokenParser userTokenParser, AuthCheckerProperties properties) {
        return new CachingSubjectResolver<>(new UserResolver(userTokenParser), properties.getUser().getTtlInSeconds(), properties.getUser().getMaximumSize());
    }

    @Bean
    public ServiceRequestAuthorizer serviceRequestAuthorizer(SubjectResolver<Service> serviceResolver, Function<HttpServletRequest, Collection<String>> authorizedServicesExtractor) {
        return new ServiceRequestAuthorizer(serviceResolver, authorizedServicesExtractor);
    }

    @Bean
    public UserRequestAuthorizer userRequestAuthorizer(SubjectResolver<User> userResolver,
                                                       Function<HttpServletRequest, Optional<String>> userIdExtractor,
                                                       Function<HttpServletRequest, Collection<String>> authorizedRolesExtractor) {
        return new UserRequestAuthorizer(userResolver, userIdExtractor, authorizedRolesExtractor);
    }

    @Bean
    public PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider() {
        PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(new AuthCheckerUserDetailsService());
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider) {
        return new ProviderManager(Collections.singletonList(preAuthenticatedAuthenticationProvider));
    }
}
