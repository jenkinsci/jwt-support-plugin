package io.jenkins.plugin.auth.jwt;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.jenkins.plugin.auth.jwt.commons.ServiceException;
import net.sf.json.JSONObject;

/**
 * Generates JWT token
 *
 * @author Vivek Pandey
 */
public class JwtToken {
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

}
