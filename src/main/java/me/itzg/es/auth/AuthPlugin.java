package me.itzg.es.auth;

import org.elasticsearch.common.inject.Module;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugins.AbstractPlugin;
import org.elasticsearch.transport.TransportModule;

import java.util.Collection;

/**
 * @author Geoff Bourne
 * @since 10/3/2015
 */
public class AuthPlugin extends AbstractPlugin {
    public String name() {
        return "auth-plugin";
    }

    public String description() {
        return "Provides authentication at the TransportService level to require authenticated clients and peers";
    }

    @Override
    public Settings additionalSettings() {
        return ImmutableSettings.settingsBuilder()
                .put(TransportModule.TRANSPORT_SERVICE_TYPE_KEY, AuthenticatingTransportService.class)
                .build();
    }
}
