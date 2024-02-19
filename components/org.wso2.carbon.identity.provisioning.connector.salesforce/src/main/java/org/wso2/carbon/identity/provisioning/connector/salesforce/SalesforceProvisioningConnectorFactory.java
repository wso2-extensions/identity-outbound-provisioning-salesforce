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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.provisioning.AbstractOutboundProvisioningConnector;
import org.wso2.carbon.identity.provisioning.AbstractProvisioningConnectorFactory;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;

import java.util.ArrayList;
import java.util.List;

public class SalesforceProvisioningConnectorFactory extends AbstractProvisioningConnectorFactory {

    private static final Log log = LogFactory.getLog(SalesforceProvisioningConnectorFactory.class);
    private static final String SALESFORCE = "salesforce";

    @Override
    protected AbstractOutboundProvisioningConnector buildConnector(
            Property[] provisioningProperties) throws IdentityProvisioningException {
        SalesforceProvisioningConnector salesforceConnector = new SalesforceProvisioningConnector();
        salesforceConnector.init(provisioningProperties);

        if (log.isDebugEnabled()) {
            log.debug("Salesforce provisioning connector created successfully.");
        }

        return salesforceConnector;
    }

    @Override
    public String getConnectorType() {
        return SALESFORCE;
    }

    /**
     * Get Configuration Properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();
        Property apiVersion = new Property();
        apiVersion.setName(SalesforceConnectorConstants.PropertyConfig.API_VERSION);
        apiVersion.setDisplayName("API version");
        apiVersion.setRequired(true);
        apiVersion.setType("string");
        apiVersion.setDisplayOrder(1);
        configProperties.add(apiVersion);

        Property domain = new Property();
        domain.setName(SalesforceConnectorConstants.PropertyConfig.DOMAIN_NAME);
        domain.setDisplayName("Domain Name");
        domain.setRequired(true);
        domain.setType("string");
        domain.setDisplayOrder(2);
        configProperties.add(domain);

        Property clientId = new Property();
        clientId.setName(SalesforceConnectorConstants.PropertyConfig.CLIENT_ID);
        clientId.setDisplayName("Client ID");
        clientId.setRequired(true);
        clientId.setType("string");
        clientId.setDisplayOrder(3);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(SalesforceConnectorConstants.PropertyConfig.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setType("string");
        clientSecret.setDisplayOrder(4);
        clientSecret.setConfidential(true);
        configProperties.add(clientSecret);

        Property grantType = new Property();
        grantType.setName(SalesforceConnectorConstants.PropertyConfig.USE_PASSWORD_GRANT);
        grantType.setDisplayName("Use OAuth Username-Password Flow to get access token");
        grantType.setType("boolean");
        grantType.setDefaultValue("true");
        grantType.setDisplayOrder(5);
        configProperties.add(grantType);

        Property username = new Property();
        username.setName(SalesforceConnectorConstants.PropertyConfig.USERNAME);
        username.setDisplayName("Username");
        username.setRequired(false);
        username.setType("string");
        username.setDisplayOrder(6);
        configProperties.add(username);

        Property password = new Property();
        password.setName(SalesforceConnectorConstants.PropertyConfig.PASSWORD);
        password.setDisplayName("Password");
        password.setRequired(false);
        password.setType("string");
        password.setDisplayOrder(7);
        password.setConfidential(true);
        configProperties.add(password);

        Property tokenEp = new Property();
        tokenEp.setName(SalesforceConnectorConstants.PropertyConfig.OAUTH2_TOKEN_ENDPOINT);
        tokenEp.setDisplayName("OAuth2 Token Endpoint");
        tokenEp.setRequired(true);
        tokenEp.setType("string");
        tokenEp.setDefaultValue("https://login.salesforce.com/services/oauth2/token");
        tokenEp.setDisplayOrder(8);
        configProperties.add(tokenEp);

        Property provPattern = new Property();
        provPattern.setName(SalesforceConnectorConstants.PropertyConfig.PROVISIONING_PATTERN_KEY);
        provPattern.setDisplayName("Provisioning Pattern");
        provPattern.setRequired(false);
        provPattern.setDescription("This pattern is used to build the user id of Salesforce domain. Combination of " +
                "attributes UD (User Domain), UN (Username), TD (Tenant Domain) and IDP (Identity Provider) can be " +
                "used to construct a valid pattern. Ex: {UD, UN, TD, IDP}");
        provPattern.setType("string");
        provPattern.setDisplayOrder(9);
        configProperties.add(provPattern);

        Property provSeperator = new Property();
        provSeperator.setName(SalesforceConnectorConstants.PropertyConfig.PROVISIONING_SEPERATOR_KEY);
        provSeperator.setDisplayName("Provisioning Separator");
        provSeperator.setRequired(false);
        provSeperator.setDescription("This is the separator of attributes in Salesforce Outbound Provisioning pattern" +
                ". For example if pattern is {UN,TD} and Username: testUser, Tenant Domain: TestTenant.com, " +
                "Separator:_, Google Domain : testmail.com then the privisioining email is testUser_testTenant" +
                ".com@testmail.com");
        provSeperator.setType("string");
        provSeperator.setDisplayOrder(10);
        configProperties.add(provSeperator);

        Property provDomain = new Property();
        provDomain.setName(SalesforceConnectorConstants.PropertyConfig.PROVISIONING_DOMAIN_KEY);
        provDomain.setDisplayName("Provisioning Domain");
        provDomain.setRequired(false);
        provDomain.setType("string");
        provDomain.setDisplayOrder(11);
        configProperties.add(provDomain);

        return configProperties;
    }
}
