package io.jenkins.plugin.auth.jwt.impl;

import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import io.jenkins.plugin.auth.jwt.JwtTokenVerifier;
import io.jenkins.plugin.commons.ServiceException;
import org.acegisecurity.Authentication;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import hudson.ExtensionList;
import jenkins.model.Jenkins;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest(JwtTokenVerifier.class)
@PowerMockIgnore("javax.security.auth.Subject")
public class JwtAuthenticationFilterTest {

    private JwtAuthenticationFilter filter = new JwtAuthenticationFilter();
    private String jwt = "MY_JWT";

    private ExtensionList<JwtTokenVerifier> verifiers = ExtensionList.create((Jenkins)null, JwtTokenVerifier.class);

    @Mock
    private HttpServletRequest request;

    @Mock
    private Authentication user;

    @Mock
    private JwtTokenVerifier firstVerifier;
    @Mock
    private JwtTokenVerifier secondVerifier;

    @Before
    public void setup() {
        PowerMockito.mockStatic(JwtTokenVerifier.class);
        verifiers.clear();
        verifiers.add(0, firstVerifier);
        when(JwtTokenVerifier.all()).thenReturn(verifiers);
    }

    @Test
    public void testVerifyToken_HappyPath() {
        when(request.getHeader("Authorization")).thenReturn("Bearer " + jwt);

        when(firstVerifier.getAuthenticationFromToken(jwt)).thenReturn(Optional.of(user));
        Authentication authentication = filter.verifyToken(request);

        assertThat(authentication, is(equalTo(user)));
    }

    @Test(expected = ServiceException.UnauthorizedException.class)
    public void testVerifyToken_VerifierThrowsException() {
        when(request.getHeader("Authorization")).thenReturn("Bearer " + jwt);

        when(firstVerifier.getAuthenticationFromToken(jwt)).thenThrow(new ServiceException.UnauthorizedException(
                "Sadness"));
        filter.verifyToken(request);
    }

    @Test
    public void testVerifyToken_FirstVerifierReturnsEmpty_SecondVerifierSucceeds() {
        // Given The first firstVerifier returns empty() because it cannot verify the token
        // And The second firstVerifier successfully verifies the token and returns the user.
        // Then the resulting Authentication should be the user
        when(request.getHeader("Authorization")).thenReturn("Bearer " + jwt);

        verifiers.add(1, secondVerifier);
        when(firstVerifier.getAuthenticationFromToken(jwt)).thenReturn(Optional.empty());
        when(secondVerifier.getAuthenticationFromToken(jwt)).thenReturn(Optional.of(user));

        Authentication authentication = filter.verifyToken(request);

        assertThat(authentication, is(equalTo(user)));
        // Verify both verifiers got called (ie, I got their indexes correct in the 'add' steps above)
        verify(firstVerifier).getAuthenticationFromToken(jwt);
        verify(secondVerifier).getAuthenticationFromToken(jwt);
    }

    @Test
    public void testVerifyToken_FirstVerifierReturnsUser_SecondVerifierNotCalled() {
        // Given The first firstVerifier returns empty() because it cannot verify the token
        // And The second firstVerifier successfully verifies the token and returns the user.
        // Then the resulting Authentication should be the user
        when(request.getHeader("Authorization")).thenReturn("Bearer " + jwt);

        verifiers.add(1, secondVerifier);
        when(firstVerifier.getAuthenticationFromToken(jwt)).thenReturn(Optional.of(user));

        Authentication authentication = filter.verifyToken(request);

        assertThat(authentication, is(equalTo(user)));
        // Verify only the first verifier got called
        verify(firstVerifier).getAuthenticationFromToken(jwt);
        verify(secondVerifier, never()).getAuthenticationFromToken(jwt);
    }
}