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
package com.adt.authservice.service;

import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.adt.authservice.exception.PasswordResetLinkException;
import com.adt.authservice.exception.ResourceAlreadyInUseException;
import com.adt.authservice.exception.ResourceNotFoundException;
import com.adt.authservice.exception.TokenRefreshException;
import com.adt.authservice.exception.UpdatePasswordException;
import com.adt.authservice.model.CustomUserDetails;
import com.adt.authservice.model.LeaveModel;
import com.adt.authservice.model.PasswordResetToken;
import com.adt.authservice.model.User;
import com.adt.authservice.model.UserDevice;
import com.adt.authservice.model.payload.LoginRequest;
import com.adt.authservice.model.payload.PasswordResetLinkRequest;
import com.adt.authservice.model.payload.PasswordResetRequest;
import com.adt.authservice.model.payload.RegistrationRequest;
import com.adt.authservice.model.payload.TokenRefreshRequest;
import com.adt.authservice.model.payload.UpdatePasswordRequest;
import com.adt.authservice.model.token.EmailVerificationToken;
import com.adt.authservice.model.token.RefreshToken;
import com.adt.authservice.repository.LeaveRepository;
import com.adt.authservice.security.JwtTokenProvider;

import javax.validation.ValidationException;

@Service
public class AuthService {

    private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());
    private final UserService userService;
    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final EmailVerificationTokenService emailVerificationTokenService;
    private final UserDeviceService userDeviceService;
    private final PasswordResetTokenService passwordResetService;


    @Autowired
    public AuthService(UserService userService, JwtTokenProvider tokenProvider, RefreshTokenService refreshTokenService, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, EmailVerificationTokenService emailVerificationTokenService, UserDeviceService userDeviceService, PasswordResetTokenService passwordResetService) {
        this.userService = userService;
        this.tokenProvider = tokenProvider;
        this.refreshTokenService = refreshTokenService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.emailVerificationTokenService = emailVerificationTokenService;
        this.userDeviceService = userDeviceService;
        this.passwordResetService = passwordResetService;

    }

    @Autowired
    private LeaveRepository leaveRepository;

    /**
     * Registers a new user in the database by performing a series of quick checks.
     *
     * @return A user object if successfully created
     */
	public Optional<User> registerUser(RegistrationRequest newRegistrationRequest) {
		validateRegistrationRequest(newRegistrationRequest);
		String newRegistrationRequestEmail = newRegistrationRequest.getEmail();
		if (emailAlreadyExists(newRegistrationRequestEmail)) {
			LOGGER.error("Email already exists: " + newRegistrationRequestEmail);
			throw new ResourceAlreadyInUseException("Email", "Address", newRegistrationRequestEmail);
		}
		if (!newRegistrationRequest.getPassword().equals(newRegistrationRequest.getConfirmPassword())) {
			LOGGER.error("Password and confirm password do not match for email: " + newRegistrationRequestEmail);
			throw new IllegalArgumentException("Password and confirm password do not match");
		}
		LOGGER.info("Trying to register new user [" + newRegistrationRequest.getFirstName() + "]");
		try {
			User newUser = userService.createUser(newRegistrationRequest);
			User registeredNewUser = userService.save(newUser);
			registeredNewUser.setPassword(UserService.originalPassword);
			return Optional.ofNullable(registeredNewUser);
		} catch (Exception e) {
			LOGGER.error(e.getMessage());
		}
		return null;
	}

	private void validateRegistrationRequest(RegistrationRequest request) {
		String[][] nameFields = { { request.getFirstName(), "First name" }, { request.getMiddleName(), "Middle name" },
				{ request.getLastName(), "Last name" } };

		for (String[] field : nameFields) {
			String name = field[0];
			String fieldName = field[1];

			if (name != null) {
				if (name.length() > 30) {
					throw new ValidationException(fieldName + " must be at most 30 characters long");
				}
				if (!name.matches("^[a-zA-Z]*$")) {
					throw new ValidationException(fieldName + " must contain only letters");
				}
			}
		}

		String emailPattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$";
		String passwordPattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*]).+$";

		if (!request.getEmail().matches(emailPattern)) {
			throw new ValidationException("Email must be a valid email address");
		}
		if (!request.getPassword().matches(passwordPattern) || !request.getConfirmPassword().matches(passwordPattern)) {
			throw new ValidationException(
					"Password and Confirm Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character");
		}
	}
    /**
     * Checks if the given email already exists in the database repository or not
     *
     * @return true if the email exists else false
     */
    public Boolean emailAlreadyExists(String email) {
        return userService.existsByEmail(email);
    }

    /**
     * Checks if the given email already exists in the database repository or not
     *
     * @return true if the email exists else false
     */
    public Boolean usernameAlreadyExists(String username) {
        return userService.existsByUsername(username);
    }

    /**
     * Authenticate user and log them in given a loginRequest
     */
    public Optional<Authentication> authenticateUser(LoginRequest loginRequest) {
        return Optional.ofNullable(authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(),
                loginRequest.getPassword())));
    }

    /**
     * Confirms the user verification based on the token expiry and mark the user as active.
     * If user is already verified, save the unnecessary database calls.
     */
    public Optional<User> confirmEmailRegistration(String emailToken) {
        EmailVerificationToken emailVerificationToken = emailVerificationTokenService.findByToken(emailToken)
                .orElseThrow(() -> new ResourceNotFoundException("Token", "Email verification", emailToken));

        User registeredUser = emailVerificationToken.getUser();
        if (registeredUser.getEmailVerified()) {
            registeredUser.setMessage("User's email is already verified.");
            LOGGER.info("User [" + emailToken + "] already registered.");
            return Optional.of(registeredUser);
        }

        emailVerificationTokenService.verifyExpiration(emailVerificationToken);
        emailVerificationToken.setConfirmedStatus();
        emailVerificationTokenService.save(emailVerificationToken);

        registeredUser.markVerificationConfirmed();
        userService.save(registeredUser);
        LeaveModel leaveModel = new LeaveModel();
        leaveModel.setEmpId(Math.toIntExact(registeredUser.getId()));
        leaveRepository.save(leaveModel);
        registeredUser.setMessage("User verified successfully!");
        return Optional.of(registeredUser);
    }

    /**
     * Attempt to regenerate a new email verification token given a valid
     * previous expired token. If the previous token is valid, increase its expiry
     * else update the token value and add a new expiration.
     */
    public Optional<EmailVerificationToken> recreateRegistrationToken(String existingToken) {
        EmailVerificationToken emailVerificationToken = emailVerificationTokenService.findByToken(existingToken)
                .orElseThrow(() -> new ResourceNotFoundException("Token", "Existing email verification", existingToken));

        if (emailVerificationToken.getUser().getEmailVerified()) {
            return Optional.empty();
        }
        return Optional.ofNullable(emailVerificationTokenService.updateExistingTokenWithNameAndExpiry(emailVerificationToken));
    }

    /**
     * Validates the password of the current logged in user with the given password
     */
   public Boolean currentPasswordMatches(User currentUser, String password) {
        return passwordEncoder.matches(password, currentUser.getPassword());
    }

    /**
     * Updates the password of the current logged in user
     */
    public Optional<User> updatePassword(CustomUserDetails customUserDetails,
                                         UpdatePasswordRequest updatePasswordRequest) {
        String email = customUserDetails.getEmail();
        User currentUser = userService.findByEmail(email)
                .orElseThrow(() -> new UpdatePasswordException(email, "No matching user found"));

        if (!currentPasswordMatches(currentUser, updatePasswordRequest.getOldPassword())) {
            LOGGER.info("Current password is invalid for [" + currentUser.getPassword() + "]");
            throw new UpdatePasswordException(currentUser.getEmail(), "Invalid current password");
        }
        String newPassword = passwordEncoder.encode(updatePasswordRequest.getNewPassword());
        currentUser.setPassword(newPassword);
        userService.save(currentUser);
        return Optional.of(currentUser);
    }

    /**
     * Generates a JWT token for the validated client
     */
    public String generateToken(CustomUserDetails customUserDetails) {
        return tokenProvider.generateToken(customUserDetails);
    }

    /**
     * Creates and persists the refresh token for the user device. If device exists
     * already, we recreate the refresh token. Unused devices with expired tokens
     * should be cleaned externally.
     */
    public Optional<RefreshToken> createAndPersistRefreshTokenForDevice(Authentication authentication, LoginRequest loginRequest) {
        User currentUser = (User) authentication.getPrincipal();
        String deviceId = loginRequest.getDeviceInfo().getDeviceId();
        userDeviceService.findDeviceByUserId(currentUser.getId(), deviceId)
                .stream()
                .map(UserDevice::getRefreshToken)
                .map(RefreshToken::getId)
                .collect(Collectors.toList())
                .forEach(refreshTokenService::deleteById);

        UserDevice userDevice = userDeviceService.createUserDevice(loginRequest.getDeviceInfo());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken();
        userDevice.setUser(currentUser);
        userDevice.setRefreshToken(refreshToken);
        refreshToken.setUserDevice(userDevice);
        refreshToken = refreshTokenService.save(refreshToken);
        return Optional.ofNullable(refreshToken);
    }

    /**
     * Refresh the expired jwt token using a refresh token and device info. The
     * * refresh token is mapped to a specific device and if it is unexpired, can help
     * * generate a new jwt. If the refresh token is inactive for a device or it is expired,
     * * throw appropriate errors.
     */
    public Optional<String> refreshJwtToken(TokenRefreshRequest tokenRefreshRequest) {
        String requestRefreshToken = tokenRefreshRequest.getRefreshToken();
        return Optional.of(refreshTokenService.findByToken(requestRefreshToken)
                        .map(refreshToken -> {
                            refreshTokenService.verifyExpiration(refreshToken);
                            userDeviceService.verifyRefreshAvailability(refreshToken);
                            refreshTokenService.increaseCount(refreshToken);
                            return refreshToken;
                        })
                        .map(RefreshToken::getUserDevice)
                        .map(UserDevice::getUser)
                        .map(CustomUserDetails::new)
                        .map(this::generateToken))
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken, "Missing refresh token in database.Please login again"));
    }

    /**
     * Generates a password reset token from the given reset request
     */
    public Optional<PasswordResetToken> generatePasswordResetToken(PasswordResetLinkRequest passwordResetLinkRequest) {
        String email = passwordResetLinkRequest.getEmail();
        LOGGER.info("ResetEmail="+email);
        return userService.findByEmail(email)
                .map(passwordResetService::createToken)
                .orElseThrow(() -> new PasswordResetLinkException(email, "No matching user found for the given request"));
    }

    /**
     * Reset a password given a reset request and return the updated user
     * The reset token must match the email for the user and cannot be used again
     * Since a user could have requested password multiple times, multiple tokens
     * would be generated. Hence, we need to invalidate all the existing password
     * reset tokens prior to changing the user password.
     */
    public Optional<User> resetPassword(PasswordResetRequest request) {
        PasswordResetToken token = passwordResetService.getValidToken(request);
        final String encodedPassword = passwordEncoder.encode(request.getConfirmPassword());
        return Optional.of(token)
                .map(passwordResetService::claimToken)
                .map(PasswordResetToken::getUser)
                .map(user -> {
                    user.setPassword(encodedPassword);
                    userService.save(user);
                    return user;
                });
    }
}
