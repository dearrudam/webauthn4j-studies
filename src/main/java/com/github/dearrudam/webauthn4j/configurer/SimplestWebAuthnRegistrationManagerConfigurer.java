package com.github.dearrudam.webauthn4j.configurer;

import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.CustomRegistrationVerifier;
import com.webauthn4j.verifier.attestation.statement.AttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.SelfAttestationTrustworthinessVerifier;

import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

import static java.util.Optional.ofNullable;

final class SimplestWebAuthnRegistrationManagerConfigurer implements
        WebAuthnRegistrationManagerConfigurer.ConfigurerObjectConverter,
        WebAuthnRegistrationManagerConfigurer.ConfigurerAttestationStatementVerifiers,
        WebAuthnRegistrationManagerConfigurer.ConfigurerCertPathTrustworthinessVerifier,
        WebAuthnRegistrationManagerConfigurer.ConfigurerSelfAttestationTrustworthinessVerifier,
        WebAuthnRegistrationManagerConfigurer.ConfigurerCustomRegistrationVerifiers,
        WebAuthnRegistrationManagerConfigurer.WebAuthnRegistrationManagerBuild {

    public static WebAuthnRegistrationManagerConfigurer.ConfigurerObjectConverter configure() {
        return new SimplestWebAuthnRegistrationManagerConfigurer();
    }

    private ObjectConverter objectConverter;
    private List<AttestationStatementVerifier> attestationStatementVerifiers;
    private CertPathTrustworthinessVerifier certPathTrustworthinessVerifier;
    private SelfAttestationTrustworthinessVerifier selfAttestationTrustworthinessVerifier;
    private List<CustomRegistrationVerifier> customRegistrationVerifiers;

    @Override
    public WebAuthnRegistrationManagerConfigurer.ConfigurerAttestationStatementVerifiers withObjectConverter(Supplier<ObjectConverter> objectConverterSupplier) {
        this.objectConverter = ofNullable(objectConverterSupplier)
                .orElseThrow(()-> new IllegalArgumentException("objectConverterSupplier must not be null"))
                .get();
        return this;
    }

    @Override
    public WebAuthnRegistrationManagerConfigurer.ConfigurerCertPathTrustworthinessVerifier withAttestationStatementVerifiers(List<AttestationStatementVerifier> attestationStatementVerifiers) {
        this.attestationStatementVerifiers = ofNullable(attestationStatementVerifiers)
                .orElseThrow(() -> new IllegalArgumentException("attestationStatementVerifiers must not be null"));
        return this;
    }

    @Override
    public WebAuthnRegistrationManagerConfigurer.ConfigurerSelfAttestationTrustworthinessVerifier withCertPathTrustworthinessVerifier(Function<ObjectConverter, CertPathTrustworthinessVerifier> certPathTrustworthinessVerifierFunction) {
        this.certPathTrustworthinessVerifier = ofNullable(certPathTrustworthinessVerifierFunction)
                .orElseThrow(() -> new IllegalArgumentException("certPathTrustworthinessVerifierFunction must not be null"))
                .apply(this.objectConverter);
        AssertUtil.notNull(this.certPathTrustworthinessVerifier, "certPathTrustworthinessVerifier must not be null");
        return this;
    }

    @Override
    public WebAuthnRegistrationManagerConfigurer.ConfigurerCustomRegistrationVerifiers withSelfAttestationTrustworthinessVerifier(Function<ObjectConverter, SelfAttestationTrustworthinessVerifier> selfAttestationTrustworthinessVerifierFunction) {
        this.selfAttestationTrustworthinessVerifier = ofNullable(selfAttestationTrustworthinessVerifierFunction)
                .orElseThrow(() -> new IllegalArgumentException("selfAttestationTrustworthinessVerifierFunction must not be null"))
                .apply(this.objectConverter);
        return this;
    }

    @Override
    public WebAuthnRegistrationManagerConfigurer.WebAuthnRegistrationManagerBuild withCustomRegistrationVerifiers(Function<ObjectConverter, List<CustomRegistrationVerifier>> customRegistrationVerifiersFunction) {
        this.customRegistrationVerifiers = ofNullable(customRegistrationVerifiersFunction)
                .orElseThrow(() -> new IllegalArgumentException("customRegistrationVerifiersFunction must not be null"))
                .apply(this.objectConverter);
        return this;
    }

    @Override
    public WebAuthnRegistrationManager build() {
        return new WebAuthnRegistrationManager(
                this.attestationStatementVerifiers,
                this.certPathTrustworthinessVerifier,
                this.selfAttestationTrustworthinessVerifier,
                this.customRegistrationVerifiers,
                this.objectConverter
        );
    }
}
