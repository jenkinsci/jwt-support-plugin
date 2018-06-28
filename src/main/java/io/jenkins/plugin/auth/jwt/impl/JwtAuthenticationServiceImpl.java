package io.jenkins.plugin.auth.jwt.impl;

import hudson.Extension;
import io.jenkins.plugin.auth.jwt.JwtAuthenticationService;
import io.jenkins.plugin.auth.jwt.JwtAuthenticationStore;
import io.jenkins.plugin.auth.jwt.JwtAuthenticationStoreFactory;
import io.jenkins.plugin.auth.jwt.JwtToken;
import jenkins.model.Jenkins;

import io.jenkins.plugin.auth.jwt.tokens.JwtGenerator;
import org.acegisecurity.Authentication;
import org.kohsuke.stapler.QueryParameter;

import javax.annotation.Nullable;

/**
 * Default implementation of {@link JwtAuthenticationService}
 *
 * @author Vivek Pandey
 */
@Extension
public class JwtAuthenticationServiceImpl extends JwtAuthenticationService {

    @Override
    public JwtToken getToken(@Nullable @QueryParameter("expiryTimeInMins") Integer expiryTimeInMins, @Nullable @QueryParameter("maxExpiryTimeInMins") Integer maxExpiryTimeInMins) {
        return JwtGenerator.all()
                    .stream()
                    .findFirst()
                    .map(generator -> generator.getToken(
                            Jenkins.getAuthentication(), expiryTimeInMins, maxExpiryTimeInMins))
                    .orElseThrow(() -> new RuntimeException("No JwtGenerators found"));
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
}

