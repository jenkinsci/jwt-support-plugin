package io.jenkins.plugin.auth.jwt;

import io.jenkins.plugin.auth.jwt.commons.JsonConverter;
import io.jenkins.plugin.auth.jwt.commons.ServiceException;
import net.sf.json.JSONObject;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.JoseException;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import java.io.IOException;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

/**
 * Generates JWT token
 *
 * @author Vivek Pandey
 */
public class JwtToken implements HttpResponse {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtToken.class);

    /**
     * JWT Claim
     */
    public final JSONObject claim = new JSONObject();

    /**
     * Generates base64 representation of JWT token sign using "RS256" algorithm
     *
     * getHeader().toBase64UrlEncode() + "." + getClaim().toBase64UrlEncode() + "." + sign
     *
     * @return base64 representation of JWT token
     */
    public String sign() {
        for(JwtTokenDecorator decorator: JwtTokenDecorator.all()){
            decorator.decorate(this);
        }

        for(JwtSigningKeyProvider signer: JwtSigningKeyProvider.all()){
            SigningKey k = signer.select(this);
            if (k!=null) {
                try {
                    JsonWebSignature jsonWebSignature = new JsonWebSignature();
                    jsonWebSignature.setPayload(claim.toString());
                    jsonWebSignature.setKey(k.getKey());
                    jsonWebSignature.setKeyIdHeaderValue(k.getKid());
                    jsonWebSignature.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
                    jsonWebSignature.setHeader(HeaderParameterNames.TYPE, "JWT");

                    return jsonWebSignature.getCompactSerialization();
                } catch (JoseException e) {
                    String msg = "Failed to sign JWT token: " + e.getMessage();
                    LOGGER.error("Failed to sign JWT token", e);
                    throw new ServiceException.UnexpectedErrorException(msg, e);
                }
            }
        }

        throw new IllegalStateException("No key is available to sign a token");
    }

    /**
     * Writes the token as an HTTP response.
     * The JWT gets used as an access token, so mimic the OAuth access token response:
     *  https://tools.ietf.org/html/rfc6749#section-4.1.4
     */
    @Override
    public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException, ServletException {
        String access_token = sign();

        int expiresIn = Integer.parseInt(claim.getString("exp")) - Integer.parseInt(claim.getString("iat"));
        OAuthAccessTokenResponse payload = new OAuthAccessTokenResponse(access_token, expiresIn);

        rsp.setContentType("application/json");
        rsp.getWriter().write(JsonConverter.toJson(payload));
    }

    @JsonNaming(value = PropertyNamingStrategy.SnakeCaseStrategy.class)
    private static final class OAuthAccessTokenResponse {
        public final String accessToken;
        public final String tokenType;
        public final int expiresIn; // seconds

        private OAuthAccessTokenResponse(String accessToken, int expiresIn) {
            this.accessToken = accessToken;
            this.tokenType = "bearer";
            this.expiresIn = expiresIn;
        }
    }
}
