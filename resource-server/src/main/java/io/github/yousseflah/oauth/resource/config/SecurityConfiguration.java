package io.github.yousseflah.oauth.resource.config;

import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
class SecurityConfiguration {

    private static final String PROTECTED_RESOURCE_METADATA_ENDPOINT_PATTERN =
            "/.well-known/oauth-protected-resource/**";

    @Bean
    @Order(1)
    SecurityFilterChain denyProtectedResourceMetadataEndpoint(HttpSecurity http) throws Exception {
        var bearerEntryPoint = new NonAdvertisingBearerTokenAuthenticationEntryPoint();

        statelessApi(http)
                // Spring Security 7.1 publishes this endpoint ahead of authorization rules;
                // shadow it to keep the requested API surface exact.
                .securityMatcher(PROTECTED_RESOURCE_METADATA_ENDPOINT_PATTERN)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().denyAll())
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(bearerEntryPoint));

        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http) throws Exception {
        var bearerEntryPoint = new NonAdvertisingBearerTokenAuthenticationEntryPoint();

        statelessApi(http)
                .authorizeHttpRequests(authorize -> authorize
                        // Permit only the container's internal error dispatch; direct /error requests remain denied.
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/hello").authenticated()
                        .anyRequest().denyAll())
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults())
                        .authenticationEntryPoint(bearerEntryPoint))
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(bearerEntryPoint));

        return http.build();
    }

    private static HttpSecurity statelessApi(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    }
}
