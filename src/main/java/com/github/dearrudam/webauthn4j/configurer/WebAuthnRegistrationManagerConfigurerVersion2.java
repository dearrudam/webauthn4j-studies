package com.github.dearrudam.webauthn4j.configurer;

import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.verifier.CustomRegistrationVerifier;
import com.webauthn4j.verifier.attestation.statement.AttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.SelfAttestationTrustworthinessVerifier;

import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

import static java.util.Optional.ofNullable;

public final class WebAuthnRegistrationManagerConfigurerVersion2 {

    private ObjectConverter objectConverter;
    private List<AttestationStatementVerifier> attestationStatementVerifiers;
    private CertPathTrustworthinessVerifier certPathTrustworthinessVerifier;
    private SelfAttestationTrustworthinessVerifier selfAttestationTrustworthinessVerifier;
    private List<CustomRegistrationVerifier> customRegistrationVerifiers;

    public static WebAuthnRegistrationManagerConfigurer.ConfigurerObjectConverter configure() {
        return new WebAuthnRegistrationManagerConfigurerVersion2.ObjectConverterConfigurer(new WebAuthnRegistrationManagerConfigurerVersion2());
    }

    private static class ObjectConverterConfigurer implements WebAuthnRegistrationManagerConfigurer.ConfigurerObjectConverter {

        private final WebAuthnRegistrationManagerConfigurerVersion2 configurer;

        public ObjectConverterConfigurer(WebAuthnRegistrationManagerConfigurerVersion2 configurer) {
            this.configurer = configurer;
        }

        @Override
        public WebAuthnRegistrationManagerConfigurer.ConfigurerAttestationStatementVerifiers withObjectConverter(Supplier<ObjectConverter> objectConverterSupplier) {
            this.configurer.objectConverter = ofNullable(objectConverterSupplier)
                    .orElseThrow(() -> new IllegalArgumentException("objectConverterSupplier must not be null"))
                    .get();
            return new WebAuthnRegistrationManagerConfigurerVersion2.AttestationStatementVerifiersConfigurer(this.configurer);
        }
    }

    private static class AttestationStatementVerifiersConfigurer implements WebAuthnRegistrationManagerConfigurer.ConfigurerAttestationStatementVerifiers {

        private final WebAuthnRegistrationManagerConfigurerVersion2 configurer;

        public AttestationStatementVerifiersConfigurer(WebAuthnRegistrationManagerConfigurerVersion2 configurer) {
            this.configurer = configurer;
        }

        @Override
        public WebAuthnRegistrationManagerConfigurer.ConfigurerCertPathTrustworthinessVerifier withAttestationStatementVerifiers(List<AttestationStatementVerifier> attestationStatementVerifiers) {
            this.configurer.attestationStatementVerifiers = ofNullable(attestationStatementVerifiers)
                    .orElseThrow(() -> new IllegalArgumentException("attestationStatementVerifiers must not be null"));
            return new WebAuthnRegistrationManagerConfigurerVersion2.CertPathTrustworthinessVerifierConfigurer(this.configurer);
        }
    }

    private static class CertPathTrustworthinessVerifierConfigurer implements WebAuthnRegistrationManagerConfigurer.ConfigurerCertPathTrustworthinessVerifier {

        private final WebAuthnRegistrationManagerConfigurerVersion2 configurer;

        public CertPathTrustworthinessVerifierConfigurer(WebAuthnRegistrationManagerConfigurerVersion2 configurer) {
            this.configurer = configurer;
        }

        @Override
        public WebAuthnRegistrationManagerConfigurer.ConfigurerSelfAttestationTrustworthinessVerifier withCertPathTrustworthinessVerifier(Function<ObjectConverter, CertPathTrustworthinessVerifier> certPathTrustworthinessVerifierFunction) {
            this.configurer.certPathTrustworthinessVerifier = ofNullable(certPathTrustworthinessVerifierFunction)
                    .orElseThrow(() -> new IllegalArgumentException("certPathTrustworthinessVerifierFunction must not be null"))
                    .apply(this.configurer.objectConverter);
            return new WebAuthnRegistrationManagerConfigurerVersion2.SelfAttestationTrustworthinessVerifierConfigurer(this.configurer);
        }

    }

    private static class SelfAttestationTrustworthinessVerifierConfigurer implements WebAuthnRegistrationManagerConfigurer.ConfigurerSelfAttestationTrustworthinessVerifier {

        private final WebAuthnRegistrationManagerConfigurerVersion2 configurer;

        public SelfAttestationTrustworthinessVerifierConfigurer(WebAuthnRegistrationManagerConfigurerVersion2 configurer) {
            this.configurer = configurer;
        }

        @Override
        public WebAuthnRegistrationManagerConfigurer.ConfigurerCustomRegistrationVerifiers withSelfAttestationTrustworthinessVerifier(Function<ObjectConverter, SelfAttestationTrustworthinessVerifier> selfAttestationTrustworthinessVerifierFunction) {
            this.configurer.selfAttestationTrustworthinessVerifier = ofNullable(selfAttestationTrustworthinessVerifierFunction)
                    .orElseThrow(() -> new IllegalArgumentException("selfAttestationTrustworthinessVerifierFunction must not be null"))
                    .apply(this.configurer.objectConverter);
            return new WebAuthnRegistrationManagerConfigurerVersion2.CustomRegistrationVerifiersConfigurer(this.configurer);
        }
    }

    private static class CustomRegistrationVerifiersConfigurer implements WebAuthnRegistrationManagerConfigurer.ConfigurerCustomRegistrationVerifiers {

        private final WebAuthnRegistrationManagerConfigurerVersion2 configurer;

        public CustomRegistrationVerifiersConfigurer(WebAuthnRegistrationManagerConfigurerVersion2 configurer) {
            this.configurer = configurer;
        }

        @Override
        public WebAuthnRegistrationManagerConfigurer.WebAuthnRegistrationManagerBuild withCustomRegistrationVerifiers(Function<ObjectConverter, List<CustomRegistrationVerifier>> customRegistrationVerifiersFunction) {
            this.configurer.customRegistrationVerifiers = ofNullable(customRegistrationVerifiersFunction)
                    .orElseThrow(() -> new IllegalArgumentException("customRegistrationVerifiersFunction must not be null"))
                    .apply(this.configurer.objectConverter);
            return new WebAuthnRegistrationManagerConfigurerVersion2.WebAuthnRegistrationManagerBuilder(this.configurer);
        }
    }

    private static class WebAuthnRegistrationManagerBuilder implements WebAuthnRegistrationManagerConfigurer.WebAuthnRegistrationManagerBuild {

        private final WebAuthnRegistrationManagerConfigurerVersion2 configurer;

        public WebAuthnRegistrationManagerBuilder(WebAuthnRegistrationManagerConfigurerVersion2 configurer) {
            this.configurer = configurer;
        }

        @Override
        public WebAuthnRegistrationManager build() {
            return new WebAuthnRegistrationManager(
                    this.configurer.attestationStatementVerifiers,
                    this.configurer.certPathTrustworthinessVerifier,
                    this.configurer.selfAttestationTrustworthinessVerifier,
                    this.configurer.customRegistrationVerifiers,
                    this.configurer.objectConverter
            );
        }
    }
}
