package org.pachkosti.security.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.pachkosti.security.service.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.Date;

@Slf4j
@Component
public class JwtUtilsNimbus {

    @Value("${org.pachkosti.app.jwtSecret}")
    private String jwtSecret;

    @Value("${org.pachkosti.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {

        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        SignedJWT signedJWT = new SignedJWT(
//                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(senderJWK.getKeyID()).build(),
                new JWSHeader.Builder(JWSAlgorithm.HS256).build(),
                new JWTClaimsSet.Builder()
                        .subject(userPrincipal.getUsername())
                        .issueTime(new Date())
                        .expirationTime(new Date((new Date()).getTime() + jwtExpirationMs))
//                        .issuer("https://c2id.com")
                        .build());

        // Sign the JWT
        try {
            signedJWT.sign(new MACSigner(jwtSecret));
        } catch (JOSEException e) {
            e.printStackTrace();
        }

        // Create JWE object with signed JWT as payload
//        JWSObject jweObject = new JWSObject(
//                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
//                        .contentType("JWT") // required to indicate nested JWT
//                        .build(),
//                new Payload(signedJWT));

        // Encrypt with the recipient's public key
//        jweObject.encrypt(new RSAEncrypter(recipientPublicJWK));

        // Serialise to JWE compact form
        String jweString = signedJWT.serialize();
        return jweString;
    }

    public String getUserNameFromJwtToken(String token) throws ParseException, JOSEException {
//        RSASSAVerifier
        return SignedJWT.parse(token).getJWTClaimsSet().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            return SignedJWT.parse(authToken).verify(new MACVerifier(jwtSecret));
        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return false;
    }
}