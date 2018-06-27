package io.jenkins.plugin.auth.jwt;

import java.util.Optional;
import hudson.ExtensionList;
import hudson.ExtensionPoint;
import io.jenkins.plugin.auth.jwt.impl.JwtTokenVerifierImpl.JwtAuthentication;
import io.jenkins.plugin.auth.jwt.commons.ServiceException;
import org.acegisecurity.Authentication;

/**
 * If an incoming HTTP request contains JWT token, pick that up, verifies the integrity, then
 * convert that into {@link JwtAuthentication} so that the rest of Jenkins can process this request
 * with proper identity of the caller.
 *
 * @author Vivek Pandey
 */
public abstract class JwtTokenVerifier implements ExtensionPoint {
    /**
     *
     * @param jwt
     *      Incoming JWT that we are trying to process
     * @return
     *      The {@link Authentication} object for the user, or Optional.empty() if no user could be found or the JWT
     *      could not be verified. Optional.empty() should also be thrown if this JWT could not be verified (as it may
     *      be verified by a subsequent verifier)
     * @throws ServiceException
     *      If the request should be explicitly denied for whatever reason. Throwing this exception will prevent
     *      all subsequent filters in the chain from executing and deny the web request, so only use this if you are
     *      certain that the JWT is not valid.
     */
    public abstract Optional<Authentication> getAuthenticationFromToken(String jwt) throws ServiceException;

    public static ExtensionList<JwtTokenVerifier> all(){
        return ExtensionList.lookup(JwtTokenVerifier.class);
    }
}
