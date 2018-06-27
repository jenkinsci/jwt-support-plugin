package io.jenkins.plugin.auth.jwt.impl;

import hudson.Extension;
import io.jenkins.plugin.auth.jwt.JwtSigningKeyProvider;
import io.jenkins.plugin.auth.jwt.JwtToken;
import io.jenkins.plugin.auth.jwt.SigningKey;
import io.jenkins.plugin.auth.jwt.SigningPublicKey;
import io.jenkins.plugin.auth.jwt.commons.ServiceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * Default {@link JwtSigningKeyProvider} that rotates a key over time.
 *
 * @author Kohsuke Kawaguchi
 * @author Vivek Pandey
 * @author Steve Arch
 */
@Extension(ordinal = -9999)
public class SigningKeyProviderImpl extends JwtSigningKeyProvider {
    private static final Logger LOGGER = Logger.getLogger(SigningKeyProviderImpl.class.getName());
    private static final Pattern YYYYMM = Pattern.compile("[0-9]{6}");
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyyMM").withZone(ZoneOffset.UTC);

    private final AtomicReference<JwtRsaDigitalSignatureKey> key = new AtomicReference<>();

    @Override
    public SigningKey select(JwtToken token) {
        String id = DATE_FORMAT.format(Instant.now());
        JwtRsaDigitalSignatureKey k = key.get();
        if (k==null || !k.getId().equals(id))
            key.set(k=new JwtRsaDigitalSignatureKey(id));
        return k.toSigningKey();
    }

    @Override
    public SigningPublicKey getPublicKey(String kid) {
        if (!YYYYMM.matcher(kid).matches())
            return null;        // not our ID. This also protects against the directory traversal attack in key ID

        JwtRsaDigitalSignatureKey key = new JwtRsaDigitalSignatureKey(kid);
        try {
            if (!key.exists()) {
                return null;
            }
        } catch (IOException e) {
            LOGGER.log(WARNING, String.format("Error reading RSA key for id %s: %s", kid, e.getMessage()), e);
            throw new ServiceException.UnexpectedErrorException("Unexpected error: " + e.getMessage(), e);
        }
        return new SigningPublicKey(kid,key.getPublicKey());
    }
}
