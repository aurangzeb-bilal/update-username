package org.gluu.agama.update;

import io.jans.as.common.model.common.User;
import io.jans.as.common.service.common.EncryptionService;
import io.jans.as.common.service.common.UserService;
import io.jans.orm.exception.operation.EntryNotFoundException;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.util.StringHelper;

import org.gluu.agama.user.UsernameUpdate;
import io.jans.agama.engine.script.LogUtils;
import java.io.IOException;
import io.jans.as.common.service.common.ConfigurationService;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.regex.Pattern;
import org.gluu.agama.smtp.SendEmailTemplate;
import org.gluu.agama.smtp.jans.model.ContextData;
import io.jans.model.SmtpConfiguration;
import io.jans.service.MailService;
import io.jans.as.server.service.IntrospectionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.Map;

public class JansUsernameUpdate extends UsernameUpdate {

    private static final String MAIL = "mail";
    private static final String UID = "uid";
    private static final String DISPLAY_NAME = "displayName";
    private static final String GIVEN_NAME = "givenName";
    private static final String LAST_NAME = "sn";
    private static final String PASSWORD = "userPassword";
    private static final String INUM_ATTR = "inum";
    private static final String EXT_ATTR = "jansExtUid";
    private static final String USER_STATUS = "jansStatus";
    private static final String EXT_UID_PREFIX = "github:";
    private static final String LANG = "lang";
    private static final SecureRandom RAND = new SecureRandom();

    private static JansUsernameUpdate INSTANCE = null;

    public JansUsernameUpdate() {
    }

    public static synchronized JansUsernameUpdate getInstance() {
        if (INSTANCE == null)
            INSTANCE = new JansUsernameUpdate();

        return INSTANCE;
    }

    public static Map<String, Object> validateBearerToken(String access_token) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            LogUtils.log("validateBearerToken called with parameter: %", access_token != null ? "not null" : "null");
            
            // Check if token is missing or empty
            if (access_token == null || access_token.trim().isEmpty()) {
                LogUtils.log("ERROR: Access token is null or empty");
                result.put("valid", false);
                result.put("error", "Access token is missing. Please provide it in the request body.");
                return result;
            }
            
            String token = access_token.trim();
            LogUtils.log("Token length: " + token.length());
            LogUtils.log("Token starts with: " + token.substring(0, Math.min(20, token.length())) + "...");
            
            // Introspect the token using the working method
            IntrospectionService introspectionService = CdiUtil.bean(IntrospectionService.class);
            LogUtils.log("Got IntrospectionService, calling introspectToken...");
            String jsonResponse = introspectionService.introspectToken(token);
            
            if (jsonResponse == null || jsonResponse.trim().isEmpty()) {
                LogUtils.log("ERROR: Introspection response is null or empty");
                result.put("valid", false);
                result.put("error", "Token introspection failed");
                return result;
            }
            
            LogUtils.log("Introspection JSON response: " + jsonResponse);
            
            // Parse the JSON response
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> introspectionMap = mapper.readValue(jsonResponse, Map.class);
            
            // Check if token is active
            Boolean active = (Boolean) introspectionMap.get("active");
            if (active == null || !active) {
                LogUtils.log("ERROR: Token is not active");
                result.put("valid", false);
                result.put("error", "Token is not active or has expired");
                return result;
            }
            
            // Get required scopes
            String scopes = (String) introspectionMap.get("scope");
            if (scopes == null || scopes.trim().isEmpty()) {
                LogUtils.log("ERROR: No scopes found in token");
                result.put("valid", false);
                result.put("error", "Token has no scopes");
                return result;
            }
            
            // Check for required scopes
            String[] requiredScopes = {"profile", "user_update", "openid"};
            boolean hasRequiredScopes = true;
            for (String requiredScope : requiredScopes) {
                if (!scopes.contains(requiredScope)) {
                    LogUtils.log("ERROR: Missing required scope: " + requiredScope);
                    hasRequiredScopes = false;
                    break;
                }
            }
            
            if (!hasRequiredScopes) {
                LogUtils.log("ERROR: Token missing required scopes");
                result.put("valid", false);
                result.put("error", "Token missing required scopes: profile, user_update, openid");
                return result;
            }
            
            // Get user info
            String username = (String) introspectionMap.get("username");
            String clientId = (String) introspectionMap.get("client_id");
            
            LogUtils.log("Token validation successful for user: " + username + ", client: " + clientId);
            
            result.put("valid", true);
            result.put("clientId", clientId);
            result.put("username", username);
            result.put("scopes", scopes);
            
        } catch (Exception e) {
            LogUtils.log("ERROR: Exception during token validation: " + e.getMessage());
            e.printStackTrace();
            result.put("valid", false);
            result.put("error", "Token validation failed: " + e.getMessage());
        }
        
        return result;
    }

    public boolean passwordPolicyMatch(String userPassword) {
        String regex = '''^(?=.*[!@#$^&*])[A-Za-z0-9!@#$^&*]{6,}$'''
        Pattern pattern = Pattern.compile(regex);
        return pattern.matcher(userPassword).matches();
    }

    public boolean usernamePolicyMatch(String userName) {
        // Regex: Only alphabets (uppercase and lowercase), minimum 1 character
        String regex = '''^[A-Za-z]+$''';
        Pattern pattern = Pattern.compile(regex);
        return pattern.matcher(userName).matches();
    }

    public Map<String, String> getUserEntityByMail(String email) {
        User user = getUser(MAIL, email);
        boolean local = user != null;
        LogUtils.log("There is % local account for %", local ? "a" : "no", email);

        if (local) {
            String uid = getSingleValuedAttr(user, UID);
            String inum = getSingleValuedAttr(user, INUM_ATTR);
            String name = getSingleValuedAttr(user, GIVEN_NAME);

            if (name == null) {
                name = getSingleValuedAttr(user, DISPLAY_NAME);
                if (name == null && email != null && email.contains("@")) {
                    name = email.substring(0, email.indexOf("@"));
                }
            }

            Map<String, String> userInfo = new HashMap<>();
            userInfo.put("uid", uid);
            userInfo.put("inum", inum);
            userInfo.put("name", name);
            userInfo.put("email", email);
            userInfo.put("local", "true");

            return userInfo;
        }

        return null;
    }

    public Map<String, String> getUserEntityByUsername(String username) {
        User user = getUser(UID, username);
        boolean local = user != null;
        LogUtils.log("There is % local account for %", local ? "a" : "user" : "no", username);

        if (local) {
            String uid = getSingleValuedAttr(user, UID);
            String inum = getSingleValuedAttr(user, INUM_ATTR);
            String name = getSingleValuedAttr(user, GIVEN_NAME);
            String email = getSingleValuedAttr(user, MAIL);

            if (name == null) {
                name = getSingleValuedAttr(user, DISPLAY_NAME);
                if (name == null && email != null && email.contains("@")) {
                    name = email.substring(0, email.indexOf("@"));
                }
            }

            Map<String, String> userInfo = new HashMap<>();
            userInfo.put("uid", uid);
            userInfo.put("inum", inum);
            userInfo.put("name", name);
            userInfo.put("email", email);
            userInfo.put("local", "true");

            return userInfo;
        }

        return null;
    }

    public Map<String, String> getUserEntityByInum(String inum) {
        User user = getUser(INUM_ATTR, inum);
        boolean local = user != null;
        LogUtils.log("There is % local account for %", local ? "a" : "no", inum);

        if (local) {
            String uid = getSingleValuedAttr(user, UID);
            String name = getSingleValuedAttr(user, GIVEN_NAME);
            String email = getSingleValuedAttr(user, MAIL);

            if (name == null) {
                name = getSingleValuedAttr(user, DISPLAY_NAME);
                if (name == null && email != null && email.contains("@")) {
                    name = email.substring(0, email.indexOf("@"));
                }
            }

            Map<String, String> userInfo = new HashMap<>();
            userInfo.put("uid", uid);
            userInfo.put("inum", inum);
            userInfo.put("name", name);
            userInfo.put("email", email);
            userInfo.put("local", "true");

            return userInfo;
        }

        return null;
    }

    public boolean updateUsername(String inum, String newUsername) {
        try {
            User user = getUser(INUM_ATTR, inum);
            if (user == null) {
                LogUtils.log("ERROR: User not found with inum: " + inum);
                return false;
            }

            // Check if new username already exists
            User existingUser = getUser(UID, newUsername);
            if (existingUser != null) {
                LogUtils.log("ERROR: Username already exists: " + newUsername);
                return false;
            }

            // Update username
            user.setAttribute(UID, newUsername);
            
            UserService userService = CdiUtil.bean(UserService.class);
            userService.updateUser(user);
            
            LogUtils.log("Username updated successfully for inum: " + inum + " to: " + newUsername);
            return true;
            
        } catch (Exception e) {
            LogUtils.log("ERROR: Failed to update username: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public boolean sendEmailNotification(String email, String oldUsername, String newUsername) {
        try {
            ConfigurationService configurationService = CdiUtil.bean(ConfigurationService.class);
            SmtpConfiguration smtpConfig = configurationService.getConfiguration().getSmtpConfiguration();
            
            if (smtpConfig == null || !smtpConfig.isEnabled()) {
                LogUtils.log("WARNING: SMTP not configured, skipping email notification");
                return false;
            }
            
            MailService mailService = CdiUtil.bean(MailService.class);
            
            String subject = "Username Update Notification";
            String body = String.format(
                "Your username has been updated from '%s' to '%s'.\n\n" +
                "If you did not request this change, please contact support immediately.",
                oldUsername, newUsername
            );
            
            mailService.sendMail(email, subject, body);
            LogUtils.log("Email notification sent to: " + email);
            return true;
            
        } catch (Exception e) {
            LogUtils.log("ERROR: Failed to send email notification: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private User getUser(String attributeName, String attributeValue) {
        try {
            UserService userService = CdiUtil.bean(UserService.class);
            return userService.getUserByAttribute(attributeName, attributeValue);
            } catch (EntryNotFoundException e) {
                return null;
            } catch (Exception e) {
                LogUtils.log("ERROR: Error getting user by %: %", attributeName, e.getMessage());
                return null;
            }
        }

    private String getSingleValuedAttr(User user, String attrName) {
        try {
            List<String> values = user.getAttributeValues(attrName);
            return values != null && !values.isEmpty() ? values.get(0) : null;
        } catch (Exception e) {
            LogUtils.log("ERROR: Error getting attribute %: %", attrName, e.getMessage());
            return null;
        }
    }
}