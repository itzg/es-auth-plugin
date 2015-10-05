package me.itzg.es.auth;

import com.google.common.base.Strings;
import com.google.common.io.BaseEncoding;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.SettingsException;
import org.elasticsearch.env.Environment;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Transport;
import org.elasticsearch.transport.TransportChannel;
import org.elasticsearch.transport.TransportException;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;
import org.elasticsearch.transport.TransportRequestOptions;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportResponseHandler;
import org.elasticsearch.transport.TransportService;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.URIParameter;

import static com.google.common.base.Strings.emptyToNull;

/**
 * @author Geoff Bourne
 * @since 10/3/2015
 */
public class AuthenticatingTransportService extends TransportService {

    public static final String HEADER_AUTHENTICATION = "Authentication";
    public static final String AUTH_TYPE_IN_MEMORY = "InMemory";
    public static final String ELASTICSEARCH_JAAS_CONF = "elasticsearch-jaas.conf";
    public static final Charset UTF_8 = StandardCharsets.UTF_8;
    public static final String DEFAULT_AUTH_TYPE = AUTH_TYPE_IN_MEMORY;

    public static final String GLOBAL_PREFIX = "auth.";
    public static final String REMOTE = "remote.";
    public static final String INCOMING = "incoming.";

    public static final String COMPONENT_REMOTE_IDENTIFIER = REMOTE + "username";
    public static final String COMPONENT_REMOTE_CREDENTIAL = REMOTE + "password";
    /**
     * Setting defaults to true if any of the {@value #REMOTE} settings are provided, but can be overridden.
     */
    public static final String COMPONENT_REMOTE_AUTHENTICATE = REMOTE + "authenticate";

    public static final String COMPONENT_REMOTE_AUTH_TYPE = REMOTE + "authType";

    public static final String COMPONENT_INCOMING_REQUIRE_AUTH = INCOMING + "required";
    /**
     * The authentication type corresponds to the JAAS application name section.
     * The initial requirement is that the incoming auth type matches the "server side" configured auth type. This
     * avoids the far-end spoofing the server end with an "alternate" JAAS entry.
     */
    public static final String COMPONENT_INCOMING_AUTH_TYPE = INCOMING + "authType";
    public static final String COMPONENT_INCOMING_JAAS_CONF = INCOMING + "jaasConf";

    public static final String SETTING_REMOTE_IDENTIFIER = GLOBAL_PREFIX + COMPONENT_REMOTE_IDENTIFIER;
    public static final String SETTING_REMOTE_CREDENTIAL = GLOBAL_PREFIX + COMPONENT_REMOTE_CREDENTIAL;
    public static final String SETTING_REMOTE_AUTHENTICATE = GLOBAL_PREFIX + COMPONENT_REMOTE_AUTHENTICATE;
    public static final String SETTING_INCOMING_REQUIRE_AUTH = GLOBAL_PREFIX + COMPONENT_INCOMING_REQUIRE_AUTH;
    public static final String SETTING_INCOMING_AUTH_TYPE = GLOBAL_PREFIX + COMPONENT_INCOMING_AUTH_TYPE;
    public static final String SETTING_INCOMING_JAAS_CONF = GLOBAL_PREFIX + COMPONENT_INCOMING_JAAS_CONF;

    private final Environment environment;

    private boolean remoteNeedsAuth;
    private boolean incomingNeedsAuth;
    private String remoteAuthEncoded;
    private String incomingExpectedAuthType;
    private Configuration jaasConfig;

    public AuthenticatingTransportService(Transport transport, ThreadPool threadPool) {
        this(ImmutableSettings.Builder.EMPTY_SETTINGS, transport, threadPool, null);
    }

    @Inject
    public AuthenticatingTransportService(Settings settings, Transport transport, ThreadPool threadPool,
                                          Environment environment) {
        super(settings, transport, threadPool);
        this.environment = environment;
        processPreStartSettings();
    }

    @Override
    protected void doStart() throws ElasticsearchException {

        processSettings();

        super.doStart();
    }

    // Public methods
    @Override
    public <T extends TransportResponse> void sendRequest(DiscoveryNode node, String action, TransportRequest request,
                                                          TransportResponseHandler<T> handler) {
        // This is invoked by super's submitRequest
        addAuthReqHeader(request);
        super.sendRequest(node, action, request, handler);
    }

    @Override
    public <T extends TransportResponse> void sendRequest(DiscoveryNode node, String action, TransportRequest request,
                                                          TransportRequestOptions options,
                                                          TransportResponseHandler<T> handler) {
        // This is invoked by super's submitRequest
        addAuthReqHeader(request);
        super.sendRequest(node, action, request, options, handler);
    }

    @Override
    public void registerHandler(String action, TransportRequestHandler handler) {
        final TransportRequestHandler securedHandler = secureHandler(handler);
        super.registerHandler(action, securedHandler);
    }

    protected void processPreStartSettings() {
        incomingNeedsAuth = getBoolSetting(COMPONENT_INCOMING_REQUIRE_AUTH, false);
    }

    // Non-public methods
    protected void processSettings() {

        remoteNeedsAuth = false;

        final String remoteUsername = emptyToNull(getStringSetting(COMPONENT_REMOTE_IDENTIFIER, null));
        if (remoteUsername != null) {
            remoteNeedsAuth = true;
        }

        String remotePassword = emptyToNull(getStringSetting(COMPONENT_REMOTE_CREDENTIAL, null));
        if (remotePassword != null) {
            if (remoteUsername == null) {
                throw new SettingsException("Password was set, but not username");
            } else {
                remoteNeedsAuth = true;
            }
        }

        // final chance to disable
        remoteNeedsAuth = getBoolSetting(COMPONENT_REMOTE_AUTHENTICATE, remoteNeedsAuth);

        if (remoteNeedsAuth) {
            final String remoteAuthType = Strings.emptyToNull(
                    getStringSetting(COMPONENT_REMOTE_AUTH_TYPE, DEFAULT_AUTH_TYPE)
            );
            if (remoteAuthType == null) {
                throw new SettingsException("Missing required " + COMPONENT_REMOTE_AUTH_TYPE);
            }

            prepareRemoteAuthEncoding(remoteAuthType, remoteUsername, remotePassword);

            logger.info("Will authenticate to remote nodes as {}", remoteUsername);
        }

        if (incomingNeedsAuth && !remoteNeedsAuth) {
            throw new SettingsException("Incoming authentication requires enabling remote authentication (for at least talk-back)");
        }

        if (incomingNeedsAuth) {
            final String jaasConf = getStringSetting(COMPONENT_INCOMING_JAAS_CONF, ELASTICSEARCH_JAAS_CONF);

            final File esJaasConf = new File(environment.configFile(), jaasConf);

            if (!esJaasConf.canRead() || !esJaasConf.isFile()) {
                throw new SettingsException("Missing required JAAS configuration file");
            }
            try {
                jaasConfig = Configuration.getInstance("JavaLoginConfig", new URIParameter(esJaasConf.toURI()));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("Unable to use JavaLoginConfig JAAS provider", e);
            }

            incomingExpectedAuthType = Strings.emptyToNull(getStringSetting(COMPONENT_INCOMING_AUTH_TYPE, null));
            if (incomingExpectedAuthType == null) {
                throw new SettingsException("Missing required " + COMPONENT_INCOMING_AUTH_TYPE);
            }
        }

    }

    protected void prepareRemoteAuthEncoding(String remoteAuthType, String remoteUsername, String remotePassword) {
        remoteAuthEncoded = remoteAuthType + " " + BaseEncoding.base64().encode(
                (remoteUsername + ":" + remotePassword).getBytes(UTF_8)
        );
    }

    protected void authenticateReceivedRequest(TransportRequest transportRequest,
                                               TransportChannel transportChannel) throws Exception {

        final String incomingAuth = transportRequest.getHeader(HEADER_AUTHENTICATION);

        if (Strings.isNullOrEmpty(incomingAuth)) {
            throw new TransportException("Failed to authenticate request: missing header");
        }

        final String[] authParts = incomingAuth.split(" ", 2);
        if (authParts.length != 2) {
            throw new TransportException("Failed to authenticate request: invalid header");
        }

        final String incomingAuthType = authParts[0];
        if (!incomingAuthType.equals(incomingExpectedAuthType)) {
            throw new TransportException("Failed to authenticate request: invalid auth type");
        }

        final String[] authDecoded = new String(BaseEncoding.base64().decode(authParts[1]), UTF_8).split(":", 2);
        if (authDecoded.length != 2) {
            throw new TransportException("Malformed decoded auth");
        }

        CallbackHandler callbackHandler = new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                for (Callback callback : callbacks) {
                    if (callback instanceof NameCallback) {
                        NameCallback nameCallback = (NameCallback) callback;
                        nameCallback.setName(authDecoded[0]);
                    } else if (callback instanceof PasswordCallback) {
                        PasswordCallback passwordCallback = (PasswordCallback) callback;
                        passwordCallback.setPassword(authDecoded[1].toCharArray());
                    }
                }
            }
        };

        final LoginContext loginContext = new LoginContext(incomingExpectedAuthType, null, callbackHandler, jaasConfig);
        loginContext.login();

    }

    protected void addAuthReqHeader(TransportRequest request) {
        if (remoteNeedsAuth) {
            request.putHeader(HEADER_AUTHENTICATION, remoteAuthEncoded);
        }
    }

    protected TransportRequestHandler secureHandler(TransportRequestHandler handler) {
        if (incomingNeedsAuth) {
            logger.trace("Securing handler: {}", handler);

            return new SecureHandlerProxy(handler);
        } else {
            return handler;
        }
    }

    private String getStringSetting(String name, String defaultValue) {
        return componentSettings.get(name, settings.get(GLOBAL_PREFIX + name, defaultValue));
    }

    private boolean getBoolSetting(String name, boolean defaultValue) {
        return componentSettings.getAsBoolean(name, settings.getAsBoolean(GLOBAL_PREFIX + name, defaultValue));
    }

    protected class SecureHandlerProxy implements TransportRequestHandler {
        private final TransportRequestHandler delegate;

        public SecureHandlerProxy(TransportRequestHandler delegate) {
            this.delegate = delegate;
        }

        // Public methods
        @Override
        public TransportRequest newInstance() {
            return delegate.newInstance();
        }

        @Override
        public void messageReceived(TransportRequest transportRequest,
                                    TransportChannel transportChannel) throws Exception {
            authenticateReceivedRequest(transportRequest, transportChannel);

            delegate.messageReceived(transportRequest, transportChannel);
        }

        @Override
        public String executor() {
            return delegate.executor();
        }

        @Override
        public boolean isForceExecution() {
            return delegate.isForceExecution();
        }
    }
}
