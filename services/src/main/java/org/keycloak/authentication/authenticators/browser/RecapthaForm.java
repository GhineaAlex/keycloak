package org.keycloak.authentication.authenticators.browser;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MultivaluedMap;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RecapthaForm extends UsernamePasswordForm implements Authenticator {
	/**
	 * Logger for this class
	 */
	private static final Logger logger = LoggerFactory.getLogger(RecapthaForm.class);
	public static final String G_RECAPTCHA_RESPONSE = "g-recaptcha-response";

	public static final String SITE_KEY = "site.key";
	public static final String SITE_SECRET = "secret";

	@Override
	public void close() {

	}

	public RecapthaForm() {
		super();

	}

	@Override
	public void action(AuthenticationFlowContext context) {
		if (logger.isDebugEnabled()) {
			logger.debug("action(AuthenticationFlowContext) - start");
		}
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		List<FormMessage> errors = new ArrayList<>();
		boolean success = false;
		context.getEvent().detail(Details.AUTH_METHOD, "auth_method");

		String captcha = formData.getFirst(G_RECAPTCHA_RESPONSE);
		if (!Validation.isBlank(captcha)) {
			AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
			String secret = captchaConfig.getConfig().get(SITE_SECRET);

			success = validateRecaptcha(context, success, captcha, secret);
		}
		if (success) {
			super.action(context);
		} else {
			errors.add(new FormMessage(null, Messages.RECAPTCHA_FAILED));
			formData.remove(G_RECAPTCHA_RESPONSE);
			return;
		}

		if (logger.isDebugEnabled()) {
			logger.debug("action(AuthenticationFlowContext) - end");
		}
	}

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

		context.getEvent().detail(Details.AUTH_METHOD, "auth_method");
		if (logger.isInfoEnabled()) {
			logger.info(
					"validateRecaptcha(AuthenticationFlowContext, boolean, String, String) - inainte de validation");
		}

		AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
		Map<String, String> econd = captchaConfig.getConfig();
		logger.debug("Am in config in context: {}", econd);
		context.form().addScript("https://www.google.com/recaptcha/api.js");
		context.form().setAttribute("recaptchaRequired", true);
		context.form().setAttribute("recaptchaSiteKey", econd.get(SITE_KEY));

		super.authenticate(context);
	}

	protected boolean validateRecaptcha(AuthenticationFlowContext context, boolean success, String captcha,
			String secret) {
		HttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
		HttpPost post = new HttpPost("https://www.google.com/recaptcha/api/siteverify");
		List<NameValuePair> formparams = new LinkedList<>();
		formparams.add(new BasicNameValuePair("secret", secret));
		formparams.add(new BasicNameValuePair("response", captcha));
		formparams.add(new BasicNameValuePair("remoteip", context.getConnection().getRemoteAddr()));

		try {
			UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
			post.setEntity(form);
			HttpResponse response = httpClient.execute(post);
			InputStream content = response.getEntity().getContent();

			try {
				Map json = JsonSerialization.readValue(content, Map.class);
				Object val = json.get("success");
				success = Boolean.TRUE.equals(val);
				// System.out.println("succes");

			} finally {
				content.close();
			}
		} catch (Exception e) {
			ServicesLogger.LOGGER.recaptchaFailed(e);
		}
		return success;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

		super.setRequiredActions(session, realm, user);

	}

}