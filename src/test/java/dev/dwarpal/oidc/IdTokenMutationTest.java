package dev.dwarpal.oidc;

import dev.dwarpal.oidc.TestTokens.Signer;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import static dev.dwarpal.oidc.TestTokens.ALL;
import static dev.dwarpal.oidc.TestTokens.NONCE;
import static dev.dwarpal.oidc.TestTokens.NOW;
import static dev.dwarpal.oidc.TestTokens.RSA_1;
import static dev.dwarpal.oidc.TestTokens.EC_1;
import static dev.dwarpal.oidc.TestTokens.ED_1;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Property-style check: whatever single byte of a valid token is changed, the token is refused, and
 * the only thing the verifier ever throws is {@link OidcException}.
 */
class IdTokenMutationTest {

    private static final int MUTATIONS_PER_ALGORITHM = 500;

    @Test
    void anySingleByteChangeIsRefusedWithAnOidcException() {
        IdTokenVerifier verifier = new IdTokenVerifier(TestTokens.policy());
        JwkSet keys = TestTokens.keySet(RSA_1, EC_1, ED_1);
        Random random = new Random(20260601L);          // fixed seed: a failure repeats
        for (Signer signer : ALL) {
            String token = TestTokens.mint(signer);
            assertEquals(signer.kid(), verifier.verify(token, keys, NONCE, NOW).keyId());
            byte[] original = token.getBytes(StandardCharsets.ISO_8859_1);
            for (int i = 0; i < MUTATIONS_PER_ALGORITHM; i++) {
                byte[] changed = original.clone();
                int at = random.nextInt(changed.length);
                byte replacement;
                do {
                    replacement = (byte) random.nextInt(256);
                } while (replacement == changed[at]);
                changed[at] = replacement;
                String mutated = new String(changed, StandardCharsets.ISO_8859_1);
                boolean accepted = false;
                try {
                    verifier.verify(mutated, keys, NONCE, NOW);
                    accepted = true;
                } catch (OidcException expected) {
                    // refused, as it must be
                } catch (RuntimeException | Error other) {
                    fail("a mutated " + signer.alg() + " token threw " + other.getClass().getName());
                }
                if (accepted) {
                    fail("a mutated " + signer.alg() + " token was accepted (byte " + at + ")");
                }
            }
        }
    }
}
