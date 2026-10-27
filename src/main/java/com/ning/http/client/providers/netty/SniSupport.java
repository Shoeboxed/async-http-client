/*
 * Copyright 2010 Ning, Inc.
 * Licensed under the Apache License, Version 2.0.
 */
package com.ning.http.client.providers.netty;

import java.net.URI;
import java.util.Collections;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

/** Configures the origin name before the TLS handshake, including through a proxy. */
final class SniSupport {
    private SniSupport() { }

    static void configure(SSLEngine engine, URI uri) {
        String host = uri.getHost();
        if (host == null || host.indexOf(':') >= 0 || host.matches("[0-9.]+")) {
            return; // IP literals are not valid SNI host names.
        }
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        SSLParameters parameters = engine.getSSLParameters();
        if (parameters.getServerNames() != null) {
            return; // Respect an explicitly configured custom SSL engine.
        }
        try {
            parameters.setServerNames(Collections.<SNIServerName>singletonList(new SNIHostName(host)));
            engine.setSSLParameters(parameters);
        } catch (IllegalArgumentException e) {
            // SNIHostName rejects invalid DNS names such as a trailing dot.
            // Let the existing connection and hostname verification handle them.
        }
    }
}
