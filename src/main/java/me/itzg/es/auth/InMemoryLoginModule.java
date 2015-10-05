package me.itzg.es.auth;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.util.Map;

/**
 * @author Geoff Bourne
 * @since 10/3/2015
 */
public class InMemoryLoginModule implements LoginModule {
    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map<String, ?> options;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
                           Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.options = options;
    }

    @Override
    public boolean login() throws LoginException {
        final NameCallback username = new NameCallback("username");
        final PasswordCallback password = new PasswordCallback("password", false);
        Callback[] callbacks = new Callback[]{
                username,
                password
        };
        try {
            callbackHandler.handle(callbacks);
        } catch (IOException | UnsupportedCallbackException e) {
            throw new LoginException();
        }

        final Object expectedUsername = options.get("username");
        final Object expectedPassword = options.get("password");

        final boolean authenticated = username.getName().equals(expectedUsername) &&
                String.valueOf(password.getPassword()).equals(expectedPassword);

        if (!authenticated) {
            throw new LoginException("Wrong username or password");
        }

        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        return true;
    }

    @Override
    public boolean commit() throws LoginException {
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return true;
    }
}
