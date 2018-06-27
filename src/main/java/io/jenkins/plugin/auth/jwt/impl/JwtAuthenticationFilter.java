package io.jenkins.plugin.auth.jwt.impl;

import hudson.Extension;
import hudson.init.Initializer;
import hudson.util.PluginServletFilter;
import io.jenkins.plugin.auth.jwt.JwtTokenVerifier;
import org.acegisecurity.Authentication;
import org.acegisecurity.context.SecurityContext;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.context.SecurityContextImpl;
import org.kohsuke.stapler.Stapler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Optional;
import com.google.common.annotations.VisibleForTesting;

/**
 * {@link Filter} that processes JWT token
 *
 * @author Kohsuke Kawaguchi
 */
@Extension
public class JwtAuthenticationFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    /**
     * Used to mark requests that had a valid JWT token.
     */
    private static final String JWT_TOKEN_VALIDATED = JwtAuthenticationFilter.class.getName()+".validated";

    private boolean isJwtEnabled = true;

    public boolean isEnabled() {
        return isJwtEnabled;
    }

    /**
     * Enable or disable JWT Authentication
     * @param enable true to enable JWT Authentication, false to disable
     */
    public void enable(boolean enable) {
        isJwtEnabled = enable;
        LOGGER.info("JWT Authentication enabled: {} ", enable);
    }

    @Initializer(fatal=false)
    public static void init() throws ServletException {
        PluginServletFilter.addFilter(new JwtAuthenticationFilter());
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        LOGGER.info("JWT Authentication enabled: {}", isJwtEnabled);
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse rsp, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;

        if(!isJwtEnabled) {
            chain.doFilter(req,rsp);
            return;
        }

        Authentication token = verifyToken(request);

        if(token==null) {
            // no JWT token found, which is fine --- we just assume the request is authenticated in other means
            // Some routes that require valid JWT token will check for the presence of JWT token during Stapler
            // request routing, not here.
            chain.doFilter(req,rsp);
            return;
        }

        // run the rest of the request with the new identity
        // create a new context and set it to holder to not clobber existing context
        SecurityContext sc = new SecurityContextImpl();
        sc.setAuthentication(token);
        SecurityContext previous = SecurityContextHolder.getContext();
        SecurityContextHolder.setContext(sc);
        request.setAttribute(JWT_TOKEN_VALIDATED,true);
        try {
            chain.doFilter(req,rsp);
        } finally {
            if(previous != null){
                SecurityContextHolder.setContext(previous);
            }else {
                SecurityContextHolder.clearContext();
            }
        }
    }

    @VisibleForTesting
    Authentication verifyToken(HttpServletRequest request) {
        // Get the token from the request
        String authHeader = request.getHeader("Authorization");
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            return null;
        }
        String token = authHeader.substring("Bearer ".length());

        return JwtTokenVerifier.all().stream()
                .map(verifier -> verifier.getAuthenticationFromToken(token))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .findFirst()
                .orElse(null);
    }

    @Override
    public void destroy() {
        // noop
    }

    /**
     * Returns true if the current request had a valid JWT token.
     */
    public static boolean didRequestHaveValidatedJwtToken() {
        return Boolean.TRUE.equals(Stapler.getCurrentRequest().getAttribute(JWT_TOKEN_VALIDATED));
    }
}
