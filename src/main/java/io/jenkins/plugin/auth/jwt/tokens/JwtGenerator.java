package io.jenkins.plugin.auth.jwt.tokens;

import javax.annotation.Nullable;

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import org.acegisecurity.Authentication;
import org.apache.tools.ant.ExtensionPoint;

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
     * @param authentication the {@link Authentication} (user) to generate a token for
     * @param expiryTimeInMins the requested expiry time in Mins
     * @param maxExpiryTimeInMins the maximum expiry time in mins
     * @return The generated token response
     */
    public abstract OAuthAccessTokenResponse getToken(Authentication authentication,
                                                      @Nullable Integer expiryTimeInMins,
                                                      @Nullable Integer maxExpiryTimeInMins);

    /**
     * Gets all {@link JwtGenerator}s
     * @return all of them
     */
    public static ExtensionList<JwtGenerator> all() {
        return Jenkins.getInstance().getExtensionList(JwtGenerator.class);
    }

    @JsonNaming(value = PropertyNamingStrategy.SnakeCaseStrategy.class)
    public static final class OAuthAccessTokenResponse {
        public final String accessToken;
        public final String tokenType;
        public final long expiresIn; // seconds

        /**
         * Create a new OAuth access token response
         * @param accessToken the access token
         * @param expiresIn the number of seconds that the token will be valid for
         */
        public OAuthAccessTokenResponse(String accessToken, long expiresIn) {
            this.accessToken = accessToken;
            this.tokenType = "bearer";
            this.expiresIn = expiresIn;
        }
    }
}
