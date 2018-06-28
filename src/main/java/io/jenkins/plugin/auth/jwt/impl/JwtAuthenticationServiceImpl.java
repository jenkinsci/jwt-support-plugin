package io.jenkins.plugin.auth.jwt.impl;

import java.io.IOException;

import hudson.Extension;
import io.jenkins.plugin.auth.jwt.JwtAuthenticationService;
import io.jenkins.plugin.auth.jwt.JwtAuthenticationStore;
import io.jenkins.plugin.auth.jwt.JwtAuthenticationStoreFactory;

import jenkins.model.Jenkins;

import io.jenkins.plugin.auth.jwt.commons.JsonConverter;
import io.jenkins.plugin.auth.jwt.tokens.JwtGenerator;
import org.acegisecurity.Authentication;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import javax.annotation.Nullable;

/**
 * Default implementation of {@link JwtAuthenticationService}
 *
 * @author Vivek Pandey
 */
@Extension
public class JwtAuthenticationServiceImpl extends JwtAuthenticationService {

    @Override
    public JwtResponse getToken(@Nullable @QueryParameter("expiryTimeInMins") Integer expiryTimeInMins, @Nullable @QueryParameter("maxExpiryTimeInMins") Integer maxExpiryTimeInMins) {
        JwtGenerator.OAuthAccessTokenResponse jwtResponse = JwtGenerator
                .all()
                .stream()
                .findFirst()
                .map(generator -> generator.getToken(Jenkins.getAuthentication(), expiryTimeInMins, maxExpiryTimeInMins))
                .orElseThrow(() -> new RuntimeException("No JwtGenerators found"));

        return new JwtResponse(jwtResponse);
    }

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return "BlueOcean Jwt endpoint";
    }

    public static JwtAuthenticationStore getJwtStore(Authentication authentication){
        JwtAuthenticationStore jwtAuthenticationStore=null;
        for(JwtAuthenticationStoreFactory factory: JwtAuthenticationStoreFactory.all()){
            if(factory instanceof SimpleJwtAuthenticationStore){
                jwtAuthenticationStore = factory.getJwtAuthenticationStore(authentication);
                continue;
            }
            JwtAuthenticationStore authenticationStore = factory.getJwtAuthenticationStore(authentication);
            if(authenticationStore != null){
                return authenticationStore;
            }
        }

        //none found, lets use SimpleJwtAuthenticationStore
        return jwtAuthenticationStore;
    }

    public static class JwtResponse implements HttpResponse {

        private final JwtGenerator.OAuthAccessTokenResponse payload;

        public JwtResponse(JwtGenerator.OAuthAccessTokenResponse response) {
            this.payload = response;
        }

        /**
         * Writes the token as an HTTP payload.
         * The JWT gets used as an access token, so mimic the OAuth access token payload:
         *  https://tools.ietf.org/html/rfc6749#section-4.1.4
         */
        @Override
        public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException {
            rsp.setContentType("application/json");
            rsp.getWriter().write(JsonConverter.toJson(payload));
        }
    }
}

