public static Map<String, Object> validateBearerToken(String access_token) {
    Map<String, Object> result = new HashMap<>();
    
    try {
        LogUtils.log("validateBearerToken called");
        LogUtils.log("Received token parameter: " + (access_token != null ? "not null" : "null"));
        
        if (access_token != null) {
            LogUtils.log("Token length: " + access_token.length());
            if (access_token.length() > 0) {
                LogUtils.log("Token starts with: " + access_token.substring(0, Math.min(30, access_token.length())) + "...");
            }
        }
        
        // Check if token is missing or empty
        if (access_token == null || access_token.trim().isEmpty()) {
            LogUtils.log("ERROR: Access token is null or empty");
            result.put("valid", false);
            result.put("error", "Access token is missing. Please provide it in the request body.");
            return result;
        }
        
        String token = access_token.trim();
        LogUtils.log("Attempting to introspect token...");
        
        // Get IntrospectionService
        IntrospectionService introspectionService = CdiUtil.bean(IntrospectionService.class);
        
        if (introspectionService == null) {
            LogUtils.log("ERROR: Could not get IntrospectionService bean");
            result.put("valid", false);
            result.put("error", "IntrospectionService not available");
            return result;
        }
        
        LogUtils.log("Got IntrospectionService, calling introspect...");
        IntrospectionResponse introspectionResponse = introspectionService.introspect(token);
        
        if (introspectionResponse == null) {
            LogUtils.log("ERROR: Introspection returned null response");
            result.put("valid", false);
            result.put("error", "Token validation failed - no introspection response");
            return result;
        }
        
        boolean isActive = introspectionResponse.isActive();
        LogUtils.log("Token active status: " + isActive);
        
        if (!isActive) {
            LogUtils.log("ERROR: Token is inactive/expired");
            result.put("valid", false);
            result.put("error", "Token is invalid or expired");
            return result;
        }
        
        // Check scopes
        String scopes = introspectionResponse.getScope();
        LogUtils.log("Token scopes: " + scopes);
        
        boolean hasRequiredScope = scopes != null && (
            scopes.contains("profile") ||
            scopes.contains("user_update") ||
            scopes.contains("openid")
        );
        
        if (!hasRequiredScope) {
            LogUtils.log("ERROR: Missing required scope. Token has: " + scopes);
            result.put("valid", false);
            result.put("error", "Token does not have required scope (profile, user_update, or openid)");
            return result;
        }
        
        String clientId = introspectionResponse.getClientId();
        String username = introspectionResponse.getUsername();
        
        LogUtils.log("SUCCESS: Token is valid for client: " + clientId);
        if (username != null) {
            LogUtils.log("Token username: " + username);
        }
        
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