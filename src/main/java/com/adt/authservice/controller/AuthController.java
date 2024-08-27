/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.adt.authservice.controller;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.mail.MessagingException;
import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.repository.query.Param;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.freemarker.FreeMarkerTemplateUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import com.adt.authservice.event.OnGenerateResetLinkEvent;
import com.adt.authservice.event.OnRegenerateEmailVerificationEvent;
import com.adt.authservice.event.OnUserAccountChangeEvent;
import com.adt.authservice.event.OnUserRegistrationCompleteEvent;
import com.adt.authservice.exception.InvalidTokenRequestException;
import com.adt.authservice.exception.PasswordResetException;
import com.adt.authservice.exception.PasswordResetLinkException;
import com.adt.authservice.exception.TokenRefreshException;
import com.adt.authservice.exception.UserLoginException;
import com.adt.authservice.exception.UserRegistrationException;
import com.adt.authservice.model.CustomUserDetails;
import com.adt.authservice.model.Role;
import com.adt.authservice.model.User;
import com.adt.authservice.model.payload.ApiResponse;
import com.adt.authservice.model.payload.JwtAuthenticationResponse;
import com.adt.authservice.model.payload.LoginRequest;
import com.adt.authservice.model.payload.LoginResponse;
import com.adt.authservice.model.payload.PasswordResetLinkRequest;
import com.adt.authservice.model.payload.PasswordResetRequest;
import com.adt.authservice.model.payload.RegistrationRequest;
import com.adt.authservice.model.payload.TokenRefreshRequest;
import com.adt.authservice.model.token.EmailVerificationToken;
import com.adt.authservice.model.token.RefreshToken;
import com.adt.authservice.security.JwtTokenProvider;
import com.adt.authservice.security.JwtTokenValidator;
import com.adt.authservice.service.ApiDetailsService;
import com.adt.authservice.service.AuthService;
import com.adt.authservice.service.OtpService;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

	private final AuthService authService;
	private final JwtTokenProvider tokenProvider;
	private final ApplicationEventPublisher applicationEventPublisher;

	@Autowired
	JwtTokenProvider jwtTokenProvider;

	@Autowired
	JwtTokenValidator jwtTokenValidator;

	@Autowired
	ApiDetailsService apiDetailsService;
	
	@Autowired
	private OtpService otpService;


	@Value("${-Dmy.port}")
	private Integer serverPort;

	@Value("${-Dmy.property}")
	private String ipaddress;

	@Value("${-UI.port}")
	private Integer uiPort;

	@Value("${-UI.property}")
	private String uiAddress;

	@Value("${-UI.scheme}")
	private String scheme;

	@Value("${-UI.context}")
	private String context;

	@Value("${app.velocity.templates.location}")
	private String basePackagePath;

	@Autowired
	private Configuration freemarkerConfig;

	@Autowired
	public AuthController(AuthService authService, JwtTokenProvider tokenProvider,
						  ApplicationEventPublisher applicationEventPublisher) {
		this.authService = authService;
		this.tokenProvider = tokenProvider;
		this.applicationEventPublisher = applicationEventPublisher;
	}

	/**
	 * Checks is a given email is in use or not.
	 */
	@GetMapping("/checkEmailInUse")
	public ResponseEntity checkEmailInUse(@RequestParam("email") String email) {
		Boolean emailExists = authService.emailAlreadyExists(email);
		return ResponseEntity.ok(new ApiResponse(true, emailExists.toString()));
	}

	/**
	 * Checks is a given username is in use or not.
	 */
	@GetMapping("/checkUsernameInUse")
	public ResponseEntity checkUsernameInUse(@RequestParam("username") String username) {
		Boolean usernameExists = authService.usernameAlreadyExists(username);
		return ResponseEntity.ok(new ApiResponse(true, usernameExists.toString()));
	}

	/**
	 * Entry point for the user log in. Return the jwt auth token and the refresh
	 * token
	 */
	@PostMapping("/login")
	public ResponseEntity authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
		Authentication authentication = authService.authenticateUser(loginRequest)
				.orElseThrow(() -> new UserLoginException("Couldn't login user [" + loginRequest + "]"));

		CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
		LOGGER.info("Logged in User returned [API]: " + customUserDetails.getUsername());
		SecurityContextHolder.getContext().setAuthentication(authentication);
		 if(otpService.validateOtp(customUserDetails.getUsername(),loginRequest.getOtp())) {
		return authService.createAndPersistRefreshTokenForDevice(authentication, loginRequest)
				.map(RefreshToken::getToken).map(refreshToken -> {
					String jwtToken = authService.generateToken(customUserDetails);
					JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse(jwtToken,
							refreshToken, tokenProvider.getExpiryDuration());
					LoginResponse loginResponse = new LoginResponse();
					loginResponse.setJwtAuthenticationResponse(jwtAuthenticationResponse);
					loginResponse.setEmployeeId(customUserDetails.getId());
					loginResponse.setEmployeeName(customUserDetails.getFirstName()+" "+customUserDetails.getLastName());
					Set<Role> roles = customUserDetails.getRoles();
					loginResponse.setRoles(apiDetailsService.getListOfApiName(roles));
					return ResponseEntity.ok(loginResponse);
				})
				.orElseThrow(() -> new UserLoginException("Couldn't create refresh token for: [" + loginRequest + "]"));
		 }
		 return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("increct OTP");
	}
	
	@PostMapping("/generatOtp")
	public ResponseEntity<?> generatOtp(@Param(value = "userName") String userName, @Param(value = "password") String password) {
		LOGGER.info("OTP generation method");
		return ResponseEntity.status(HttpStatus.OK).body(otpService.generatOtp(userName, password));
	}

	/**
	 * Entry point for the user registration process. On successful registration,
	 * publish an event to generate email verification token
	 */
	@PreAuthorize("@auth.allow('REGISTER_USER')")
	@PostMapping("/register")
	public ResponseEntity registerUser(@Valid @RequestBody RegistrationRequest registrationRequest) {
		LOGGER.info("name" + registrationRequest.getFirstName());
		return authService.registerUser(registrationRequest).map(user -> {
			UriComponentsBuilder urlBuilder = ServletUriComponentsBuilder.newInstance().scheme(scheme).host(ipaddress)
					.port(serverPort).path(context + "/api/auth/registrationConfirmation");
			OnUserRegistrationCompleteEvent onUserRegistrationCompleteEvent = new OnUserRegistrationCompleteEvent(user,
					urlBuilder);
			applicationEventPublisher.publishEvent(onUserRegistrationCompleteEvent);
			LOGGER.info("Registered User returned [API[: " + user);
			return ResponseEntity
					.ok(new ApiResponse(true, "User registered successfully. Check your email for verification"));
		}).orElseThrow(
				() -> new UserRegistrationException(registrationRequest.getEmail(), "Missing user object in database"));
	}

	/**
	 * Receives the reset link request and publishes an event to send email id
	 * containing the reset link if the request is valid. In future the deeplink
	 * should open within the app itself.
	 */
	@PostMapping("/password/resetlink")
	public ResponseEntity resetLink(@Valid @RequestBody PasswordResetLinkRequest passwordResetLinkRequest) {
		LOGGER.info("ResetPassword");
		return authService.generatePasswordResetToken(passwordResetLinkRequest).map(passwordResetToken -> {
			UriComponentsBuilder urlBuilder = ServletUriComponentsBuilder.newInstance()
					.scheme(scheme)
					.host(uiAddress)
					.port(uiPort)
					.path("/NewpassForm");
			OnGenerateResetLinkEvent generateResetLinkMailEvent = new OnGenerateResetLinkEvent(passwordResetToken,
					urlBuilder);
			LOGGER.info("Reset Password is proccessing");
			applicationEventPublisher.publishEvent(generateResetLinkMailEvent);
			return ResponseEntity.ok(new ApiResponse(true, "Password reset link sent successfully"));
		}).orElseThrow(() -> new PasswordResetLinkException(passwordResetLinkRequest.getEmail(),
				"Couldn't create a valid token"));
	}

	/**
	 * Receives a new passwordResetRequest and sends the acknowledgement after
	 * changing the password to the user's mail through the event.
	 */


	@PostMapping("/password/reset")
	public ResponseEntity resetPassword(@Valid @RequestBody PasswordResetRequest passwordResetRequest) {
		LOGGER.info("passwordReset");
		return authService.resetPassword(passwordResetRequest).map(changedUser -> {
			OnUserAccountChangeEvent onPasswordChangeEvent = new OnUserAccountChangeEvent(changedUser, "Reset Password",
					"Changed Successfully");
			applicationEventPublisher.publishEvent(onPasswordChangeEvent);
			return ResponseEntity.ok(new ApiResponse(true, "Password changed successfully"));
		}).orElseThrow(
				() -> new PasswordResetException(passwordResetRequest.getToken(), "Error in resetting password"));
	}

	/**
	 * Confirm the email verification token generated for the user during
	 * registration. If token is invalid or token is expired, report error.
	 */
	@GetMapping("/registrationConfirmation")
	public ResponseEntity<String> confirmRegistration(@RequestParam("token") String token) throws TemplateException, MessagingException, IOException {
		LOGGER.info("registrationConfirmation");
		Optional<User> optionalUser = authService.confirmEmailRegistration(token);
		freemarkerConfig.setClassForTemplateLoading(getClass(), basePackagePath);
		Template template = freemarkerConfig.getTemplate("message.ftl");
		Map<String, Object> model = new HashMap<>();
		if (optionalUser.isPresent()) {
			User user = optionalUser.get();
			model.put("Message", user.getMessage());
		} else {
			throw new InvalidTokenRequestException("Email Verification Token", token,
					"Failed to confirm email. Please generate a new email verification request.");
		}
		String emailContent = FreeMarkerTemplateUtils.processTemplateIntoString(template, model);
		return ResponseEntity.ok(emailContent);
	}

	/**
	 * Resend the email registration mail with an updated token expiry. Safe to
	 * assume that the user would always click on the last re-verification email and
	 * any attempts at generating new token from past (possibly archived/deleted)
	 * tokens should fail and report an exception.
	 */
	@GetMapping("/resendRegistrationToken")
	public ResponseEntity resendRegistrationToken(@RequestParam("token") String existingToken) {
		LOGGER.info("resendRegistrationToken");
		EmailVerificationToken newEmailToken = authService.recreateRegistrationToken(existingToken)
				.orElseThrow(() -> new InvalidTokenRequestException("Email Verification Token", existingToken,
						"User is already registered. No need to re-generate token"));

		return Optional.ofNullable(newEmailToken.getUser()).map(registeredUser -> {
			UriComponentsBuilder urlBuilder = ServletUriComponentsBuilder.newInstance()
					.scheme(scheme)
					.host(ipaddress)
					.port(serverPort)
					.path(context+"/api/auth/registrationConfirmation");
			OnRegenerateEmailVerificationEvent regenerateEmailVerificationEvent = new OnRegenerateEmailVerificationEvent(
					registeredUser, urlBuilder, newEmailToken);
			applicationEventPublisher.publishEvent(regenerateEmailVerificationEvent);
			return ResponseEntity.ok(new ApiResponse(true, "Email verification resent successfully"));
		}).orElseThrow(() -> new InvalidTokenRequestException("Email Verification Token", existingToken,
				"No user associated with this request. Re-verification denied"));
	}

	/**
	 * Refresh the expired jwt token using a refresh token for the specific device
	 * and return a new token to the caller
	 */
	@PostMapping("/refresh")
	public ResponseEntity refreshJwtToken(@Valid @RequestBody TokenRefreshRequest tokenRefreshRequest) {
		return authService.refreshJwtToken(tokenRefreshRequest).map(updatedToken -> {
			String refreshToken = tokenRefreshRequest.getRefreshToken();
			LOGGER.info("Created new Jwt Auth token: " + updatedToken);
			return ResponseEntity
					.ok(new JwtAuthenticationResponse(updatedToken, refreshToken, tokenProvider.getExpiryDuration()));
		}).orElseThrow(() -> new TokenRefreshException(tokenRefreshRequest.getRefreshToken(),
				"Unexpected error during token refresh. Please ̥and login again."));
	}





}
