package com.adt.authservice.service;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.mail.MessagingException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.ui.freemarker.FreeMarkerTemplateUtils;

import com.adt.authservice.model.Mail;

import freemarker.core.ParseException;
import freemarker.template.Configuration;
import freemarker.template.MalformedTemplateNameException;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateNotFoundException;

@Service
public class OtpService {
	@Autowired
	MailService mailService;

	@Value("${spring.mail.username}")
	private String mailFrom;

	@Value("${app.velocity.templates.location}")
	private String basePackagePath;

	private Configuration templateConfiguration;

	private final Map<String, String> otpCache = new HashMap<>();

	public String generateOtp(String username) {
		String otp = String.valueOf(new Random().nextInt(999999));
		otpCache.put(username, otp);
		mailService.sendMail(username, otp);
		return otp;
	}

	public boolean validateOtp(String username, String otp) {
		if (otp.equals(otpCache.get(username))) {
			otpCache.remove(username);
			return true;
		}
		return false;
	}

}
