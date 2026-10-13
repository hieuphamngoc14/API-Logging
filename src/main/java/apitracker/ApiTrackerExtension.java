package apitracker;

import apitracker.util.Log;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/** Extension entry point (Montoya). */
public final class ApiTrackerExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("API Logging");
        Log.init(api.logging());
        new App(api).initialize();
    }
}
