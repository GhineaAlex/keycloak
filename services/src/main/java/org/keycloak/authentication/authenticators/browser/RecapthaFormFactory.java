package org.keycloak.authentication.authenticators.browser;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RecapthaFormFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {
	/**
	 * Logger for this class
	 */
	private static final Logger logger = LoggerFactory.getLogger(RecapthaFormFactory.class);

	public static final String SITE_SECRET = "secret";
	public static final String SITE_KEY = "site.key";
	public static final String RECAPTCHA_REFERENCE_CATEGORY = "recaptcha";
	public static final String PROVIDER_ID = "login-recaptcha-action";
	public static final RecapthaForm SINGLETON = new RecapthaForm();

	@Override
	public Authenticator create(KeycloakSession session) {

		RecapthaForm returnAuthenticator = SINGLETON;
		return returnAuthenticator;
	}

	@Override
	public void init(Config.Scope config) {

	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {

	}

	@Override
	public void close() {

	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getReferenceCategory() {
		return RECAPTCHA_REFERENCE_CATEGORY;
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
			AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED };

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public String getDisplayType() {
		return "Recapthca and username password form";
	}

	@Override
	public String getHelpText() {
		return "Adds Google Recaptcha button.  Recaptchas verify that the entity that is registering is a human.  This can only be used on the internet and must be configured after you add it.";
	}

	private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

	static {
		ProviderConfigProperty property = new ProviderConfigProperty();
		property.setName(SITE_KEY);
		property.setLabel("Recaptcha Site Key");
		property.setType(ProviderConfigProperty.STRING_TYPE);
		property.setHelpText("Google Recaptcha Site Key");
		configProperties.add(property);
		property = new ProviderConfigProperty();
		property.setName(SITE_SECRET);
		property.setLabel("Recaptcha Secret");
		property.setType(ProviderConfigProperty.STRING_TYPE);
		property.setHelpText("Google Recaptcha Secret");
		configProperties.add(property);
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return configProperties;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return false;
	}



}