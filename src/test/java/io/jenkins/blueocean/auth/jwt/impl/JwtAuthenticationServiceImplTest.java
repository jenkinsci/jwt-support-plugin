package io.jenkins.blueocean.auth.jwt.impl;

import com.gargoylesoftware.htmlunit.Page;
import hudson.model.User;
import hudson.tasks.Mailer;
import net.sf.json.JSONObject;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwx.JsonWebStructure;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.Map;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsInstanceOf.instanceOf;

/**
 * @author Vivek Pandey
 */
public class JwtAuthenticationServiceImplTest {

    public static final String APPLICATION_JSON = "application/json";
    @Rule
    public JenkinsRule j = new JenkinsRule();

    private JenkinsRule.WebClient webClient;

    @Before
    public void setup() {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        webClient = j.createWebClient();
    }

    @Test
    public void getAndUseToken() throws Exception {
        User user = User.getById("alice", true);
        user.setFullName("Alice Cooper");
        user.addProperty(new Mailer.UserProperty("alice@jenkins-ci.org"));

        webClient.login("alice");

        String token = getToken(webClient);

        Assert.assertNotNull(token);

        JsonWebStructure jsonWebStructure = JsonWebStructure.fromCompactSerialization(token);

        Assert.assertTrue(jsonWebStructure instanceof JsonWebSignature);

        JsonWebSignature jsw = (JsonWebSignature) jsonWebStructure;

        System.out.println(token);
        System.out.println(jsw.toString());


        String kid = jsw.getHeader("kid");

        Assert.assertNotNull(kid);

        Page page = webClient.goTo("jwt-auth/jwks/"+kid+"/", APPLICATION_JSON);

        JSONObject jsonObject = JSONObject.fromObject(page.getWebResponse().getContentAsString());
        System.out.println(jsonObject.toString());
        RsaJsonWebKey rsaJsonWebKey = new RsaJsonWebKey(jsonObject,null);

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setRequireExpirationTime() // the JWT must have an expiration time
            .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
            .setRequireSubject() // the JWT must have a subject claim
            .setVerificationKey(rsaJsonWebKey.getKey()) // verify the sign with the public key
            .build(); // create the JwtConsumer instance

        JwtClaims claims = jwtConsumer.processToClaims(token);
        Assert.assertEquals("alice",claims.getSubject());

        Map<String,Object> claimMap = claims.getClaimsMap();

        Map<String,Object> context = (Map<String, Object>) claimMap.get("context");
        Map<String,String> userContext = (Map<String, String>) context.get("user");
        Assert.assertEquals("alice", userContext.get("id"));
        Assert.assertEquals("Alice Cooper", userContext.get("fullName"));
        Assert.assertEquals("alice@jenkins-ci.org", userContext.get("email"));
    }

    @Test
    public void anonymousUserToken() throws Exception{
        String token = getToken(webClient);
        Assert.assertNotNull(token);

        JsonWebStructure jsonWebStructure = JsonWebStructure.fromCompactSerialization(token);

        Assert.assertTrue(jsonWebStructure instanceof JsonWebSignature);

        JsonWebSignature jsw = (JsonWebSignature) jsonWebStructure;


        String kid = jsw.getHeader("kid");

        Assert.assertNotNull(kid);

        Page page = webClient.goTo("jwt-auth/jwks/"+kid+"/", APPLICATION_JSON);

        JSONObject jsonObject = JSONObject.fromObject(page.getWebResponse().getContentAsString());
        RsaJsonWebKey rsaJsonWebKey = new RsaJsonWebKey(jsonObject,null);

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setRequireExpirationTime() // the JWT must have an expiration time
            .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
            .setRequireSubject() // the JWT must have a subject claim
            .setVerificationKey(rsaJsonWebKey.getKey()) // verify the sign with the public key
            .build(); // create the JwtConsumer instance

        JwtClaims claims = jwtConsumer.processToClaims(token);
        Assert.assertEquals("anonymous",claims.getSubject());

        Map<String,Object> claimMap = claims.getClaimsMap();

        Map<String,Object> context = (Map<String, Object>) claimMap.get("context");
        Map<String,String> userContext = (Map<String, String>) context.get("user");
        Assert.assertEquals("anonymous", userContext.get("id"));
    }

    @Test
    public void testGetTokenResponse() throws IOException, SAXException {
        Page page = webClient.goTo("jwt-auth/token/", APPLICATION_JSON);
        JSONObject response = JSONObject.fromObject(page.getWebResponse().getContentAsString());

        assertThat(response.get("access_token"), instanceOf(String.class));
        assertThat(response.getString("access_token"), not(isEmptyOrNullString()));
        assertThat(response.get("token_type"), is(equalTo("bearer")));
        assertThat(response.get("expires_in"), is(equalTo(1_800))); // default expiry time
    }

    @Test
    public void testGetTokenResponseForOneHour() throws IOException, SAXException {
        Page page = webClient.goTo("jwt-auth/token/?expiryTimeInMins=60", APPLICATION_JSON);
        JSONObject response = JSONObject.fromObject(page.getWebResponse().getContentAsString());

        assertThat(response.get("expires_in"), is(equalTo(3_600))); // default expiry time
    }

    private String getToken(JenkinsRule.WebClient webClient) throws IOException, SAXException {
        Page page = webClient.goTo("jwt-auth/token/", APPLICATION_JSON);
        JSONObject response = JSONObject.fromObject(page.getWebResponse().getContentAsString());
        return response.getString("access_token");
    }
}
