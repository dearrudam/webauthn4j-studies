package com.github.dearrudam.webauthn4j.configurer;

import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.verifier.CustomRegistrationVerifier;
import com.webauthn4j.verifier.attestation.statement.AttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.apple.AppleAnonymousAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.SelfAttestationTrustworthinessVerifier;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

public interface WebAuthnRegistrationManagerConfigurer {

    interface ConfigurerObjectConverter {

        default ConfigurerAttestationStatementVerifiers withDefaultObjectConverter() {
            return withObjectConverter(ObjectConverter::new);
        }

        ConfigurerAttestationStatementVerifiers withObjectConverter(Supplier<ObjectConverter> objectConverterSupplier);

        default ConfigurerSelfAttestationTrustworthinessVerifier withCertPathTrustworthinessVerifier(
                Function<ObjectConverter, CertPathTrustworthinessVerifier> certPathTrustworthinessVerifierFunction){
            return withDefaultObjectConverter()
                    .withDefaultAttestationStatementVerifiers()
                    .withCertPathTrustworthinessVerifier(certPathTrustworthinessVerifierFunction);
        }

    }

    interface ConfigurerAttestationStatementVerifiers {

        ConfigurerCertPathTrustworthinessVerifier withAttestationStatementVerifiers(
                List<AttestationStatementVerifier> attestationStatementVerifiers);

        default ConfigurerCertPathTrustworthinessVerifier withDefaultAttestationStatementVerifiers() {
            return withAttestationStatementVerifiers(
                    Arrays.asList(
                            new PackedAttestationStatementVerifier(),
                            new FIDOU2FAttestationStatementVerifier(),
                            new AndroidKeyAttestationStatementVerifier(),
                            new AndroidSafetyNetAttestationStatementVerifier(),
                            new TPMAttestationStatementVerifier(),
                            new AppleAnonymousAttestationStatementVerifier(),
                            new NoneAttestationStatementVerifier()
                    ));
        }

        default ConfigurerSelfAttestationTrustworthinessVerifier withCertPathTrustworthinessVerifier(
                Function<ObjectConverter, CertPathTrustworthinessVerifier> certPathTrustworthinessVerifierFunction){
            return withDefaultAttestationStatementVerifiers()
                    .withCertPathTrustworthinessVerifier(certPathTrustworthinessVerifierFunction);
        }
    }


    interface ConfigurerCertPathTrustworthinessVerifier {

        ConfigurerSelfAttestationTrustworthinessVerifier withCertPathTrustworthinessVerifier(
                Function<ObjectConverter, CertPathTrustworthinessVerifier> certPathTrustworthinessVerifierFunction);

    }

    interface ConfigurerSelfAttestationTrustworthinessVerifier {

        ConfigurerCustomRegistrationVerifiers withSelfAttestationTrustworthinessVerifier(
                Function<ObjectConverter, SelfAttestationTrustworthinessVerifier> selfAttestationTrustworthinessVerifierFunction
        );

        default ConfigurerCustomRegistrationVerifiers withDefaultSelfAttestationTrustworthinessVerifier() {
            return withSelfAttestationTrustworthinessVerifier(objectConverter -> new DefaultSelfAttestationTrustworthinessVerifier());
        }

        default WebAuthnRegistrationManager build(){
            return withDefaultSelfAttestationTrustworthinessVerifier()
                    .withNoCustomRegistrationVerifiers()
                    .build();
        }
    }

    interface ConfigurerCustomRegistrationVerifiers {

        WebAuthnRegistrationManagerBuild withCustomRegistrationVerifiers(
                Function<ObjectConverter, List<CustomRegistrationVerifier>> customRegistrationVerifiersFunction);

        default WebAuthnRegistrationManagerBuild withNoCustomRegistrationVerifiers(){
            return withCustomRegistrationVerifiers(objectConverter -> Collections.emptyList());
        }

    }

    interface WebAuthnRegistrationManagerBuild {

        WebAuthnRegistrationManager build();

    }

}
