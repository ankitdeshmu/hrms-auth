package com.adt.authservice.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.adt.authservice.model.User;
import com.adt.authservice.repository.UserRepository;
import com.adt.authservice.util.TableDataExtractor;

@Service
public class OtpService {
	@Autowired
	MailService mailService;

	@Value("${spring.mail.username}")
	private String mailFrom;

	@Value("${app.velocity.templates.location}")
	private String basePackagePath;

	@Value("${otp.duration.time}")
	private int otpDurationLimit;

	@Autowired
	private TableDataExtractor dataExtractor;

	@Autowired
	private AuthService authService;

	@Autowired
	UserRepository userRepository;

	private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

	private final Map<String, Map<String, Long>> otpCache = new HashMap<>();

	public String generatOtp(String username, String password) {
		try {
			Optional<User> user = userRepository.findByEmail(username);
			LOGGER.info("user info:" + user);
			if (user.isPresent()) {
				User users = user.get();
				if (validateUser(users, password)) {
					Map<String, Long> storeOtp = new HashMap<>();
					String otp = String.valueOf(new Random().nextInt(999999));
					otpCache.put(username, storeOtp);
					mailService.sendMail(username, otp);
					long currentTime = System.currentTimeMillis();
					LOGGER.info("OTP time:" + currentTime);
					storeOtp.put(otp, currentTime);
					return "OTP successfully generated";
				}
				return "Password is Incurrect";
			}
			return "User not found";
		} catch (Exception e) {
			LOGGER.error(" exception in generatOtp method" + e.getMessage());
			return e.getMessage();
		}
	}

	public boolean validateOtp(String userName, String otp) {
		try {
			String sql = "SELECT * FROM av_schema.configuration where functionality='email_varification'";
			LOGGER.info("username" + userName);
			boolean status = false;
			List<Map<String, Object>> otpData = dataExtractor.extractDataFromTable(sql);
			for (Map<String, Object> otpStatus : otpData) {
				status = Boolean.parseBoolean(String.valueOf(otpStatus.get("status")));
			}
			LOGGER.info("status" + status);
			if (!status) {
				return true;
			}
			Map<String, Long> generatedTime = otpCache.get(userName);
			if (generatedTime != null) {
				Set<String> keys = generatedTime.keySet();
				List<String> keyList = new ArrayList<>(keys);
				if (otp.equals(keyList.get(0))) {
					long oldTime = generatedTime.get(otp);
					long currentTime = System.currentTimeMillis();
					long duration = currentTime - oldTime;
					if (duration <= otpDurationLimit) {
						otpCache.remove(userName);
						return true;
					}

					return false;
				}
				return false;
			}
			return false;
		} catch (Exception e) {
			LOGGER.error("exception in validate OTP method " + e.getMessage());
			return false;
		}

	}

	public boolean validateUser(User user, String password) {
		LOGGER.info("validateUser method");
		return authService.currentPasswordMatches(user, password);
	}

}
