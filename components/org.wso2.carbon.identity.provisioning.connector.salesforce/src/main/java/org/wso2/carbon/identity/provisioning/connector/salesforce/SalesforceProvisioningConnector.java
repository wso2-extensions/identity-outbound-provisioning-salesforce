/*
 *  Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.provisioning.connector.salesforce;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.provisioning.AbstractOutboundProvisioningConnector;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningConstants;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;
import org.wso2.carbon.identity.provisioning.ProvisionedIdentifier;
import org.wso2.carbon.identity.provisioning.ProvisioningEntity;
import org.wso2.carbon.identity.provisioning.ProvisioningEntityType;
import org.wso2.carbon.identity.provisioning.ProvisioningOperation;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

public class SalesforceProvisioningConnector extends AbstractOutboundProvisioningConnector {

    private static final long serialVersionUID = 8465869197181038416L;

    private static final Log log = LogFactory.getLog(SalesforceProvisioningConnector.class);
    private SalesforceProvisioningConnectorConfig configHolder;

    @Override
    public void init(Property[] provisioningProperties) throws IdentityProvisioningException {
        Properties configs = new Properties();

        if (provisioningProperties != null && provisioningProperties.length > 0) {
            for (Property property : provisioningProperties) {
                configs.put(property.getName(), property.getValue());
                if (IdentityProvisioningConstants.JIT_PROVISIONING_ENABLED.equals(property.getName()) && "1"
                        .equals(property.getValue())) {
                    jitProvisioningEnabled = true;
                }
            }
        }

        configHolder = new SalesforceProvisioningConnectorConfig(configs);
    }

    @Override
    public ProvisionedIdentifier provision(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {
        String provisionedId = null;

        if (provisioningEntity != null) {

            if (provisioningEntity.isJitProvisioning() && !isJitProvisioningEnabled()) {
                log.debug("JIT provisioning disabled for Salesforce connector");
                return null;
            }

            if (provisioningEntity.getEntityType() == ProvisioningEntityType.USER) {
                if (provisioningEntity.getOperation() == ProvisioningOperation.DELETE) {
                    deleteUser(provisioningEntity);
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.POST) {
                    provisionedId = createUser(provisioningEntity);
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.PUT) {
                    update(provisioningEntity.getIdentifier().getIdentifier(), buildJsonObject(provisioningEntity));
                } else {
                    log.warn("Unsupported provisioning opertaion.");
                }
            } else {
                log.warn("Unsupported provisioning opertaion.");
            }
        }

        // creates a provisioned identifier for the provisioned user.
        ProvisionedIdentifier identifier = new ProvisionedIdentifier();
        identifier.setIdentifier(provisionedId);
        return identifier;
    }

    /**
     * @param provisioningEntity
     * @return
     * @throws IdentityProvisioningException
     */
    private JSONObject buildJsonObject(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {

        boolean isDebugEnabled = log.isDebugEnabled();

        String provisioningPattern = this.configHolder
                .getValue(SalesforceConnectorConstants.PropertyConfig.PROVISIONING_PATTERN_KEY);
        if (StringUtils.isBlank(provisioningPattern)) {
            log.info("Provisioning pattern is not defined, hence using default provisioning pattern");
            provisioningPattern = SalesforceConnectorConstants.PropertyConfig.DEFAULT_PROVISIONING_PATTERN;
        }
        String provisioningSeparator = this.configHolder
                .getValue(SalesforceConnectorConstants.PropertyConfig.PROVISIONING_SEPERATOR_KEY);
        if (StringUtils.isBlank(provisioningSeparator)) {
            log.info("Provisioning separator is not defined, hence using default provisioning separator");
            provisioningSeparator = SalesforceConnectorConstants.PropertyConfig.DEFAULT_PROVISIONING_SEPERATOR;
        }
        String idpName = this.configHolder.getValue(SalesforceConnectorConstants.PropertyConfig.IDP_NAME_KEY);

        JSONObject user = new JSONObject();

        try {
            /**
             * Mandatory properties : 12 and this will vary according to API Version
             *
             * Alias, Email, EmailEncodingKey, LanguageLocaleKey, LastName, LocaleSidKey, ProfileId,
             * TimeZoneSidKey, User-name, UserPermissionsCallCenterAutoLogin,
             * UserPermissionsMarketingUser, UserPermissionsOfflineUser
             **/

            Map<String, String> requiredAttributes = getSingleValuedClaims(provisioningEntity.getAttributes());

            String userIdClaimURL = this.configHolder
                    .getValue(SalesforceConnectorConstants.PropertyConfig.USER_ID_CLAIM_URI_KEY);
            String provisioningDomain = this.configHolder
                    .getValue(SalesforceConnectorConstants.PropertyConfig.PROVISIONING_DOMAIN_KEY);
            String userId = provisioningEntity.getEntityName();

            if (StringUtils.isNotBlank(requiredAttributes.get(userIdClaimURL))) {
                userId = requiredAttributes.get(userIdClaimURL);
            }

            String userIdFromPattern = null;

            if (provisioningPattern != null) {
                userIdFromPattern = buildUserId(provisioningEntity, provisioningPattern, provisioningSeparator,
                        idpName);
            }
            if (StringUtils.isNotBlank(userIdFromPattern)) {
                userId = userIdFromPattern;
            }

            if (StringUtils.isBlank(userId)) {
                throw new IdentityProvisioningException("Cannot Find Username Attribute for Provisioning");
            }

            if (StringUtils.isNotBlank(provisioningDomain) && !userId.endsWith(provisioningDomain)) {
                userId = userId.replaceAll("@", ".").concat("@").concat(provisioningDomain);
            }
            requiredAttributes.put(SalesforceConnectorConstants.USERNAME_ATTRIBUTE, userId);

            Iterator<Entry<String, String>> iterator = requiredAttributes.entrySet().iterator();

            while (iterator.hasNext()) {
                Map.Entry<String, String> mapEntry = iterator.next();
                if ("true".equals(mapEntry.getValue())) {
                    user.put(mapEntry.getKey(), true);
                } else if ("false".equals(mapEntry.getValue())) {
                    user.put(mapEntry.getKey(), false);
                } else {
                    user.put(mapEntry.getKey(), mapEntry.getValue());
                }
                if (isDebugEnabled) {
                    log.debug("The key is: " + mapEntry.getKey() + " , value is: " + mapEntry.getValue());
                }
            }

            if (isDebugEnabled) {
                log.debug("JSON object of User\n" + user.toString(2));
            }

        } catch (JSONException e) {
            log.error("Error while creating JSON body");
            throw new IdentityProvisioningException(e);
        }

        return user;
    }

    /**
     * @param provisioningEntity
     * @return
     * @throws IdentityProvisioningException
     */
    private String createUser(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {

        boolean isDebugEnabled = log.isDebugEnabled();

        String provisionedId = null;
        try (CloseableHttpClient httpclient = HttpClientBuilder.create().useSystemProperties().build()) {
            JSONObject user = buildJsonObject(provisioningEntity);

            HttpPost post = new HttpPost(this.getUserObjectEndpoint());
            setAuthorizationHeader(post);

            post.setEntity(new StringEntity(user.toString(),
                    ContentType.create(SalesforceConnectorConstants.CONTENT_TYPE_APPLICATION_JSON)));

            try (CloseableHttpResponse response = httpclient.execute(post)) {

                if (isDebugEnabled) {
                    log.debug("HTTP status " + response.getStatusLine().getStatusCode() + " creating user");
                }

                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_CREATED) {
                    JSONObject jsonResponse = new JSONObject(
                            new JSONTokener(new InputStreamReader(response.getEntity().getContent())));
                    if (isDebugEnabled) {
                        log.debug("Create response: " + jsonResponse.toString(2));
                    }

                    if (jsonResponse.getBoolean("success")) {
                        provisionedId = jsonResponse.getString("id");
                        if (isDebugEnabled) {
                            log.debug("New record id " + provisionedId);
                        }
                    }
                } else {
                    log.error("Received response status code: " + response.getStatusLine().getStatusCode() + " text: "
                            + response.getStatusLine().getReasonPhrase());
                    if (isDebugEnabled) {
                        log.debug("Error response : " + readResponse(post));
                    }
                }
            } catch (IOException | JSONException e) {
                throw new IdentityProvisioningException("Error in invoking provisioning operation for the user", e);
            } finally {
                post.releaseConnection();
            }

            if (isDebugEnabled) {
                log.debug("Returning created user's ID: " + provisionedId);
            }
        } catch (IOException e) {
            log.error("Error while closing HttpClient.");
        }
        return provisionedId;
    }

    private String readResponse(HttpPost post) throws IOException {
        try (InputStream is = post.getEntity().getContent()) {
            BufferedReader rd = new BufferedReader(new InputStreamReader(is));
            String line;
            StringBuilder response = new StringBuilder();
            while ((line = rd.readLine()) != null) {
                response.append(line);
                response.append('\r');
            }
            rd.close();
            return response.toString();
        }
    }

    /**
     * @param provisioningEntity
     * @throws IdentityProvisioningException
     */
    private void deleteUser(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {

        JSONObject entity = new JSONObject();
        try {
            entity.put(SalesforceConnectorConstants.IS_ACTIVE, false);
            entity.put(SalesforceConnectorConstants.USERNAME_ATTRIBUTE, alterUsername(provisioningEntity));
            update(provisioningEntity.getIdentifier().getIdentifier(), entity);
        } catch (JSONException e) {
            log.error("Error while creating JSON body");
            throw new IdentityProvisioningException(e);
        }
    }

    /**
     * @param provsionedId
     * @param entity
     * @return
     * @throws IdentityProvisioningException
     */
    private void update(String provsionedId, JSONObject entity) throws IdentityProvisioningException {

        boolean isDebugEnabled = log.isDebugEnabled();

        HttpPost patch = new HttpPost(this.getUserObjectEndpoint() + provsionedId) {
            @Override
            public String getMethod() {
                return "PATCH";
            }
        };

        setAuthorizationHeader(patch);
        patch.setEntity(new StringEntity(entity.toString(),
                ContentType.create(SalesforceConnectorConstants.CONTENT_TYPE_APPLICATION_JSON)));

        try (CloseableHttpClient httpclient = HttpClientBuilder.create().useSystemProperties().build()) {
            try (CloseableHttpResponse response = httpclient.execute(patch)) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK
                        || response.getStatusLine().getStatusCode() == HttpStatus.SC_NO_CONTENT) {
                    if (isDebugEnabled) {

                        log.debug("HTTP status " + response.getStatusLine().getStatusCode() + " updating user " +
                                provsionedId + "\n\n");
                    }
                } else {
                    log.error("Received response status code: " + response.getStatusLine().getStatusCode() + " text: "
                            + response.getStatusLine().getStatusCode());
                    if (isDebugEnabled) {
                        log.debug("Error response: " + readResponse(patch));
                    }
                }
            } catch (IOException e) {
                log.error("Error in invoking provisioning request");
                throw new IdentityProvisioningException(e);
            }

        } catch (IOException e) {
            log.error("Error while closing HttpClient.");
        } finally {
            patch.releaseConnection();
        }

    }

    /**
     * adding OAuth authorization headers to a httpMethod
     *
     * @param httpMethod method which wants to add Authorization header
     */
    private void setAuthorizationHeader(HttpRequestBase httpMethod) throws IdentityProvisioningException {

        boolean isDebugEnabled = log.isDebugEnabled();

        String accessToken = authenticate();
        if (StringUtils.isNotBlank(accessToken)) {
            httpMethod.addHeader(SalesforceConnectorConstants.AUTHORIZATION_HEADER_NAME,
                    SalesforceConnectorConstants.AUTHORIZATION_HEADER_OAUTH + " " + accessToken);

            if (isDebugEnabled) {
                log.debug("Setting authorization header for method: " + httpMethod.getMethod() + " as follows,");
                Header authorizationHeader = httpMethod
                        .getLastHeader(SalesforceConnectorConstants.AUTHORIZATION_HEADER_NAME);
                log.debug(authorizationHeader.getName() + ": " + authorizationHeader.getValue());
            }
        } else {
            throw new IdentityProvisioningException("Authentication failed");
        }

    }

    /**
     * authenticate to salesforce API.
     */
    private String authenticate() throws IdentityProvisioningException {

        boolean isDebugEnabled = log.isDebugEnabled();

        try (CloseableHttpClient httpclient = HttpClientBuilder.create().useSystemProperties().build()) {

            String url = configHolder.getValue(SalesforceConnectorConstants.PropertyConfig.OAUTH2_TOKEN_ENDPOINT);

            HttpPost post = new HttpPost(
                    StringUtils.isNotBlank(url) ? url : IdentityApplicationConstants.SF_OAUTH2_TOKEN_ENDPOINT);

            List<BasicNameValuePair> params = new ArrayList<>();

            params.add(new BasicNameValuePair(SalesforceConnectorConstants.CLIENT_ID,
                    configHolder.getValue(SalesforceConnectorConstants.PropertyConfig.CLIENT_ID)));
            params.add(new BasicNameValuePair(SalesforceConnectorConstants.CLIENT_SECRET,
                    configHolder.getValue(SalesforceConnectorConstants.PropertyConfig.CLIENT_SECRET)));
            params.add(new BasicNameValuePair(SalesforceConnectorConstants.PASSWORD,
                    configHolder.getValue(SalesforceConnectorConstants.PropertyConfig.PASSWORD)));
            params.add(new BasicNameValuePair(SalesforceConnectorConstants.GRANT_TYPE,
                    SalesforceConnectorConstants.GRANT_TYPE_PASSWORD));
            params.add(new BasicNameValuePair(SalesforceConnectorConstants.USERNAME,
                    configHolder.getValue(SalesforceConnectorConstants.PropertyConfig.USERNAME)));

            post.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();
            try (CloseableHttpResponse response = httpclient.execute(post)) {
                // send the request

                if (isDebugEnabled) {
                    log.debug("Authentication to salesforce returned with response code: " + response.getStatusLine()
                            .getStatusCode());
                }

                sb.append("HTTP status " + response.getStatusLine().getStatusCode() + " creating user\n\n");

                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    JSONObject jsonResponse = new JSONObject(
                            new JSONTokener(new InputStreamReader(response.getEntity().getContent())));
                    if (isDebugEnabled) {
                        log.debug("Authenticate response: " + jsonResponse.toString(2));
                    }

                    Object attributeValObj = jsonResponse.opt("access_token");
                    if (attributeValObj instanceof String) {
                        if (isDebugEnabled) {
                            log.debug("Access token is: " + (String) attributeValObj);
                        }
                        return (String) attributeValObj;
                    } else {
                        log.error("Authentication response type: " + attributeValObj.toString() + " is invalide");
                    }
                } else {
                    log.error("Received response status code: " + response.getStatusLine().getStatusCode() + " text: "
                            + response.getStatusLine().getReasonPhrase());
                }
            } catch (JSONException | IOException e) {
                throw new IdentityProvisioningException("Error in decoding response to JSON", e);
            } finally {
                post.releaseConnection();
            }
        } catch (IOException e) {
            log.error("Error while closing HttpClient.");
        }

        return "";
    }

    /**
     * builds salesforce user end point using configurations
     *
     * @return
     */
    private String getUserObjectEndpoint() {

        boolean isDebugEnabled = log.isDebugEnabled();

        String url = configHolder.getValue(SalesforceConnectorConstants.PropertyConfig.DOMAIN_NAME)
                + SalesforceConnectorConstants.CONTEXT_SERVICES_DATA + configHolder
                .getValue(SalesforceConnectorConstants.PropertyConfig.API_VERSION)
                + SalesforceConnectorConstants.CONTEXT_SOOBJECTS_USER;
        if (isDebugEnabled) {
            log.debug("Built user endpoint url : " + url);
        }

        return url;
    }

    /**
     * Builds Salesforce query point using configurations
     *
     * @return
     */
    private String getDataQueryEndpoint() {
        if (log.isTraceEnabled()) {
            log.trace("Starting getDataQueryEndpoint() of " + SalesforceProvisioningConnector.class);
        }
        boolean isDebugEnabled = log.isDebugEnabled();

        String url = configHolder.getValue(SalesforceConnectorConstants.PropertyConfig.DOMAIN_NAME)
                + SalesforceConnectorConstants.CONTEXT_SERVICES_DATA + configHolder
                .getValue(SalesforceConnectorConstants.PropertyConfig.API_VERSION)
                + SalesforceConnectorConstants.CONTEXT_QUERY;
        if (isDebugEnabled) {
            log.debug("Built query endpoint url: " + url);
        }

        return url;
    }

    /**
     * @return
     * @throws IdentityProvisioningException
     */
    public String listUsers(String query) throws IdentityProvisioningException {

        if (log.isTraceEnabled()) {
            log.trace("Starting listUsers() of " + SalesforceProvisioningConnector.class);
        }
        boolean isDebugEnabled = log.isDebugEnabled();

        if (StringUtils.isBlank(query)) {
            query = SalesforceConnectorDBQueries.SALESFORCE_LIST_USER_SIMPLE_QUERY;
        }

        StringBuilder sb = new StringBuilder();
        try (CloseableHttpClient httpclient = HttpClientBuilder.create().useSystemProperties().build()) {
            HttpGet get = new HttpGet(this.getDataQueryEndpoint());
            setAuthorizationHeader(get);

            try {
                // set the SOQL as a query param
                URI uri = new URIBuilder(get.getURI()).addParameter("q", query).build();
                get.setURI(uri);
            } catch (URISyntaxException e) {
                throw new IdentityProvisioningException("Error in Building the URI", e);
            }

            try (CloseableHttpResponse response = httpclient.execute(get)) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {

                    JSONObject jsonResponse = new JSONObject(
                            new JSONTokener(new InputStreamReader(response.getEntity().getContent())));
                    if (isDebugEnabled) {
                        log.debug("Query response: " + jsonResponse.toString(2));
                    }

                    // Build the returning string
                    sb.append(jsonResponse.getString("totalSize") + " record(s) returned\n\n");
                    JSONArray results = jsonResponse.getJSONArray("records");
                    for (int i = 0; i < results.length(); i++) {
                        sb.append(results.getJSONObject(i).getString("Id") + ", " + results.getJSONObject(i)
                                .getString("Alias") + ", " + results.getJSONObject(i).getString("Email") + ", " +
                                results.getJSONObject(i).getString("LastName") + ", " +
                                results.getJSONObject(i).getString("Name") + ", " + results.getJSONObject(i)
                                .getString("ProfileId") + ", " + results.getJSONObject(i).getString("Username") +
                                "\n");
                    }
                    sb.append("\n");
                } else {
                    log.error("Received response status code: " + response.getStatusLine().getStatusCode() + " text: "
                            + response.getStatusLine().getReasonPhrase());
                }
            } catch (JSONException | IOException e) {
                log.error("Error in invoking provisioning operation for the user listing");
                throw new IdentityProvisioningException(e);
            } finally {
                get.releaseConnection();
            }

            if (isDebugEnabled) {
                log.debug("Returning string: " + sb.toString());
            }

            if (log.isTraceEnabled()) {
                log.trace("Ending listUsers() of " + SalesforceProvisioningConnector.class);
            }
        } catch (IOException e) {
            log.error("Error while closing HttpClient.");
        }
        return sb.toString();
    }

    /**
     * Alter username while changing user to active state to inactive state. This is necessary when adding previously
     * deleted users.
     *
     * @param provisioningEntity
     * @return
     * @throws IdentityProvisioningException
     */
    protected String alterUsername(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {

        if (StringUtils.isBlank(provisioningEntity.getEntityName())) {
            throw new IdentityProvisioningException("Could Not Find Entity Name from Provisioning Entity");
        }
        String alteredUsername =
                SalesforceConnectorConstants.SALESFORCE_OLD_USERNAME_PREFIX + UUIDGenerator.generateUUID()
                        + provisioningEntity.getEntityName();

        if (log.isDebugEnabled()) {
            log.debug("Alter username: " + provisioningEntity.getEntityName() + " to: " + alteredUsername
                    + "while deleting user");
        }
        return alteredUsername;
    }
}
