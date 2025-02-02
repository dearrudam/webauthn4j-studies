package com.github.dearrudam.webauthn4j.mds;


import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.FidoMDS3MetadataBLOBProvider;
import com.webauthn4j.metadata.MetadataBLOBProvider;
import com.webauthn4j.metadata.anchor.MetadataBLOBBasedTrustAnchorRepository;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBFactory;
import com.webauthn4j.util.CertificateUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class WebAuthnMetadataLoader {

    static final Logger logger = LoggerFactory.getLogger(WebAuthnMetadataLoader.class);


    public static void main(String[] args) {

        // Read more about FIDO Metadata Service: https://fidoalliance.org/metadata/

        // The site suggests to downloading the BLOB once a month and then caching its
        // content because the MDS data does not change often.

        ObjectConverter objectConverter = new ObjectConverter();

        MetadataBLOBBasedTrustAnchorRepository repository = getMetadataBLOBBasedTrustAnchorRepository(objectConverter);

        AAGUID aaguid = new AAGUID("b93fd961-f2e6-462f-b122-82002247de78");

        System.out.println("AAGUID: " + aaguid);
        Set<TrustAnchor> trustAnchors = repository.find(aaguid);

        System.out.println(trustAnchors);

    }

    public static MetadataBLOBBasedTrustAnchorRepository getMetadataBLOBBasedTrustAnchorRepository(ObjectConverter objectConverter) {
        MetadataBLOBFactory metadataBLOBFactory = new MetadataBLOBFactory(objectConverter);

        MetadataBLOB metadataBLOB = metadataBLOBFactory.parse(readStringFromURL("https://mds3.fidoalliance.org/"));

        MetadataBLOBBasedTrustAnchorRepository repository = new MetadataBLOBBasedTrustAnchorRepository(() -> metadataBLOB);

        return repository;
    }

    private static String readStringFromURL(String url) {
        return readStringFromURL(new LinkedHashSet<>(),url);
    }

    private static String readStringFromURL(Set<String> accessedUrls, String url) {
        if (!accessedUrls.add(url)) {
            // redirect loop detected
            throw new RuntimeException("Redirect loop detected: %s".formatted(accessedUrls));
        }

        try {

            var request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .build();

            var response = HttpClient.newHttpClient()
                    .send(request, HttpResponse.BodyHandlers.ofString());

            logger.info("Response from {} : {}", url, response);

            if (response.statusCode() >= 300 && response.statusCode() < 400) {
                // should follow the redirect
                String location = response.headers().firstValue("location").orElseThrow(
                        () -> new RuntimeException(
                                "Cannot found the location HTTP header to redirect from URL: %s".formatted(url)));

                logger.info("Redirecting from {} to {}", url, location);
                return readStringFromURL(accessedUrls, location);
            }

            if (response.statusCode() != 200) {
                throw new RuntimeException("Failed to load data from %s : Status Code: %s . Response: %s".formatted(url, response.statusCode(), response.body()));
            }
            return response.body();
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Failed to read from URL: %s".formatted(url), e);
        }
    }

    private static Endpoints loadEndpoints(String endpoint) {

        try {

            ObjectMapper objectMapper = new ObjectMapper();

            var requestBody = objectMapper.createObjectNode().put("endpoint", endpoint).toString();

            var request = HttpRequest.newBuilder()
                    .uri(URI.create("https://mds3.fido.tools/getEndpoints"))
                    .header("Content-Type", "application/json")
                    .POST(BodyPublishers.ofString(requestBody))
                    .build();

            var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Failed to load endpoints: Status Code: %s . Response: %s".formatted(response.statusCode(), response.body()));
            }

            return objectMapper.readValue(response.body(), Endpoints.class);

        } catch (IOException e) {
            throw new RuntimeException("Failure to GET the endpoints for %s".formatted(endpoint), e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private static X509Certificate loadCertificateFromURL(String url) {
        try {
            byte[] data = HttpClient.newHttpClient()
                    .send(HttpRequest.newBuilder(URI.create(url)).GET().build(),
                            HttpResponse.BodyHandlers.ofByteArray())
                    .body();
            return CertificateUtil.generateX509Certificate(data);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    static record Endpoints(String status, List<String> result) {
        @JsonCreator
        Endpoints(@JsonProperty("status") String status, @JsonProperty("result") List<String> result) {
            this.status = status;
            this.result = result;
        }
    }

    static MetadataBLOBBasedTrustAnchorRepository metadataBLOBBasedTrustAnchorRepository(ObjectConverter objectConverter, String endpoint) {

        X509Certificate mds3TestRootCertificate = loadCertificateFromURL("https://mds3.fido.tools/pki/MDS3ROOT.crt");

        Endpoints endpoints = loadEndpoints(endpoint);

        MetadataBLOBProvider[] fidoMDS3MetadataBLOBProviders = endpoints
                .result()
                .stream()
                .parallel()
                .<MetadataBLOBProvider>mapMulti((url, downstream) -> {
                    try {
                        FidoMDS3MetadataBLOBProvider fidoMDS3MetadataBLOBProvider = new FidoMDS3MetadataBLOBProvider(objectConverter, url, mds3TestRootCertificate);
                        fidoMDS3MetadataBLOBProvider.setRevocationCheckEnabled(true);
                        fidoMDS3MetadataBLOBProvider.provide();
                        downstream.accept(fidoMDS3MetadataBLOBProvider);
                    } catch (RuntimeException e) {
                        logger.warn("Failed to provide metadataBLOB from %s".formatted(url), e);
                    }
                })
                .toArray(MetadataBLOBProvider[]::new);
        return new MetadataBLOBBasedTrustAnchorRepository(fidoMDS3MetadataBLOBProviders);
    }

}
