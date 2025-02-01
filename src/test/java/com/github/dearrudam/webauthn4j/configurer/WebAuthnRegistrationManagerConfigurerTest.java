package com.github.dearrudam.webauthn4j.configurer;

import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

class WebAuthnRegistrationManagerConfigurerTest {

    @Test
    void configure_usingSimplestWebAuthnRegistrationManagerConfigurer() {
        assertThatThrownBy(() ->
                SimplestWebAuthnRegistrationManagerConfigurer
                        .configure()
                        .withCertPathTrustworthinessVerifier(objectConverter -> mock(CertPathTrustworthinessVerifier.class))
                        .build())
                .as("""
                        SimplestWebAuthnRegistrationManagerConfigurer is not a valid builder based the overloaded methods used 
                        in the implementation are called instead of the default methods declared in the interfaces.
                        """)
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void configure_usingWebAuthnRegistrationManagerConfigurerVersion2() {

        assertThat(WebAuthnRegistrationManagerConfigurerVersion2
                .configure()
                .withCertPathTrustworthinessVerifier(objectConverter -> mock(CertPathTrustworthinessVerifier.class))
                .build())
                .isNotNull();
    }
}