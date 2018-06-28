package io.jenkins.plugin.auth.jwt.tokens;

import javax.annotation.Nullable;

import org.acegisecurity.Authentication;
import org.apache.tools.ant.ExtensionPoint;
import io.jenkins.plugin.auth.jwt.JwtToken;

import hudson.ExtensionList;
import jenkins.model.Jenkins;

/**
 * An {@link org.apache.tools.ant.ExtensionPoint} that allows for JWT generation. Many {@link JwtGenerator}s can be
 * defined to run in Jenkins. The {@link JwtGenerator} with the largest ordinal will be used by Jenkins to generate
 * a JWT for the user
 */
public abstract class JwtGenerator extends ExtensionPoint {

    /**
     * Get a token for the given user.
     *
     * @param authentication the {@link Authentication} (user) to generate a {@link JwtToken} for
     * @param expiryTimeInMins the requested expiry time in Mins
     * @param maxExpiryTimeInMins the maximum expiry time in mins
     * @return The generated {@link JwtToken}
     */
    public abstract JwtToken getToken(Authentication authentication,
                                      @Nullable Integer expiryTimeInMins,
                                      @Nullable Integer maxExpiryTimeInMins);

    /**
     * Gets all {@link JwtGenerator}s
     * @return all of them
     */
    public static ExtensionList<JwtGenerator> all() {
        return Jenkins.getInstance().getExtensionList(JwtGenerator.class);
    }
}
