package io.jenkins.plugin.auth.jwt.tokens;

import java.util.Collections;
import java.util.UUID;
import javax.annotation.Nullable;

import org.acegisecurity.Authentication;
import org.kohsuke.stapler.QueryParameter;
import io.jenkins.plugin.auth.jwt.JwtAuthenticationStore;
import io.jenkins.plugin.auth.jwt.JwtAuthenticationStoreFactory;
import io.jenkins.plugin.auth.jwt.JwtToken;
import io.jenkins.plugin.auth.jwt.commons.ServiceException;
import io.jenkins.plugin.auth.jwt.impl.SimpleJwtAuthenticationStore;
import net.sf.json.JSONObject;

import hudson.Extension;
import hudson.Plugin;
import hudson.model.User;
import hudson.security.AccessDeniedException2;
import hudson.tasks.Mailer;
import jenkins.model.Jenkins;

/**
 * A {@link JwtGenerator} that generates an internally signed JWT.
 */
@Extension(ordinal = -999)
public class InternalJwtGenerator extends JwtGenerator {

    private static int DEFAULT_EXPIRY_IN_SEC = 1800;
    private static int DEFAULT_MAX_EXPIRY_TIME_IN_MIN = 480;
    private static int DEFAULT_NOT_BEFORE_IN_SEC = 30;

    public static JwtAuthenticationStore getJwtStore(Authentication authentication) {
        JwtAuthenticationStore jwtAuthenticationStore = null;
        for (JwtAuthenticationStoreFactory factory : JwtAuthenticationStoreFactory.all()) {
            if (factory instanceof SimpleJwtAuthenticationStore) {
                jwtAuthenticationStore = factory.getJwtAuthenticationStore(authentication);
                continue;
            }
            JwtAuthenticationStore authenticationStore = factory.getJwtAuthenticationStore(authentication);
            if (authenticationStore != null) {
                return authenticationStore;
            }
        }

        //none found, lets use SimpleJwtAuthenticationStore
        return jwtAuthenticationStore;
    }

    @Override
    public OAuthAccessTokenResponse getToken(Authentication authentication,
                                             @Nullable @QueryParameter("expiryTimeInMins") Integer expiryTimeInMins,
                                             @Nullable @QueryParameter("maxExpiryTimeInMins") Integer maxExpiryTimeInMins) {
        JwtToken jwtToken = generateJwt(authentication, expiryTimeInMins, maxExpiryTimeInMins);
        String signedToken = jwtToken.sign();

        int expiresIn = Integer.parseInt(jwtToken.claim.getString("exp")) -
                        Integer.parseInt(jwtToken.claim.getString("iat"));
        return new OAuthAccessTokenResponse(signedToken, expiresIn);
    }

    private JwtToken generateJwt(Authentication authentication,
                                 @Nullable @QueryParameter("expiryTimeInMins") Integer expiryTimeInMins,
                                 @Nullable @QueryParameter("maxExpiryTimeInMins") Integer maxExpiryTimeInMins) {
        long expiryTime = Long.getLong("EXPIRY_TIME_IN_MINS", DEFAULT_EXPIRY_IN_SEC);

        int maxExpiryTime = Integer.getInteger("MAX_EXPIRY_TIME_IN_MINS", DEFAULT_MAX_EXPIRY_TIME_IN_MIN);

        if (maxExpiryTimeInMins != null) {
            maxExpiryTime = maxExpiryTimeInMins;
        }
        if (expiryTimeInMins != null) {
            if (expiryTimeInMins > maxExpiryTime) {
                throw new ServiceException.BadRequestException(
                        String.format("expiryTimeInMins %s can't be greater than %s", expiryTimeInMins, maxExpiryTime));
            }
            expiryTime = expiryTimeInMins * 60;
        }

        String userId = authentication.getName();

        User user = User.get(userId, false, Collections.emptyMap());
        String email = null;
        String fullName = null;
        if (user != null) {
            fullName = user.getFullName();
            userId = user.getId();
            Mailer.UserProperty p = user.getProperty(Mailer.UserProperty.class);
            if (p != null)
                email = p.getAddress();
        }
        Plugin plugin = Jenkins.getInstance().getPlugin("plugin-jwt");
        String issuer = "plugin-jwt:" + ((plugin != null) ? plugin.getWrapper().getVersion() : "");

        JwtToken jwtToken = new JwtToken();
        jwtToken.claim.put("jti", UUID.randomUUID().toString().replace("-", ""));
        jwtToken.claim.put("iss", issuer);
        jwtToken.claim.put("sub", userId);
        jwtToken.claim.put("name", fullName);
        long currentTime = System.currentTimeMillis() / 1000;
        jwtToken.claim.put("iat", currentTime);
        jwtToken.claim.put("exp", currentTime + expiryTime);
        jwtToken.claim.put("nbf", currentTime - DEFAULT_NOT_BEFORE_IN_SEC);

        //set claim
        JSONObject context = new JSONObject();

        JSONObject userObject = new JSONObject();
        userObject.put("id", userId);
        userObject.put("fullName", fullName);
        userObject.put("email", email);

        JwtAuthenticationStore authenticationStore = getJwtStore(authentication);

        authenticationStore.store(authentication, context);

        context.put("user", userObject);
        jwtToken.claim.put("context", context);
        return jwtToken;
    }
}
