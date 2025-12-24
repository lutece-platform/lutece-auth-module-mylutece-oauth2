![](https://dev.lutece.paris.fr/jenkins/buildStatus/icon?job=auth-module-myoauth2-deploy)
[![Alerte](https://dev.lutece.paris.fr/sonar/api/project_badges/measure?project=fr.paris.lutece.plugins%3Amodule-mylutece-oauth2&metric=alert_status)](https://dev.lutece.paris.fr/sonar/dashboard?id=fr.paris.lutece.plugins%3Amodule-mylutece-oauth2)
[![Line of code](https://dev.lutece.paris.fr/sonar/api/project_badges/measure?project=fr.paris.lutece.plugins%3Amodule-mylutece-oauth2&metric=ncloc)](https://dev.lutece.paris.fr/sonar/dashboard?id=fr.paris.lutece.plugins%3Amodule-mylutece-oauth2)
[![Coverage](https://dev.lutece.paris.fr/sonar/api/project_badges/measure?project=fr.paris.lutece.plugins%3Amodule-mylutece-oauth2&metric=coverage)](https://dev.lutece.paris.fr/sonar/dashboard?id=fr.paris.lutece.plugins%3Amodule-mylutece-oauth2)

# Module MyLutece pour FranceConnect

![](https://dev.lutece.paris.fr/plugins/module-mylutece-oauth2/images/franceconnect.png)

## Introduction

Ce module s'appuie sur le [plugin FranceConnect](https://github.com/lutece-platform/lutece-auth-plugin-franceconnect.git) pour réaliser une authentification MyLutece basée sur un fournisseur d'identités de la plate-forme FranceConnect.

# Configuration

## Configuration Properties (mylutece-oauth2.properties)

Module configuration parameters are managed in the `WEB-INF/conf/plugins/mylutece-oauth2.properties` file.
Authentication Service
| Parameter| Description| Default Value|
|-----------------|-----------------|-----------------|
|  `mylutece.url.login.page` | OAuth2 service login page| servlet/plugins/oauth2/callback?data_client=authData|
|  `mylutece.url.doLogout` | Logout page| jsp/site/Portal.jsp?page=oauth2&action=dologout|
|  `mylutece-oauth2.service.name` | Name of the authentication service| Lutece Oauth2 Authentication Service|
|  `mylutece-oauth2.error.page` | Error handling page| jsp/site/Portal.jsp?page=oauth2|
Prompt None Management
| Parameter| Description| Default Value|
|-----------------|-----------------|-----------------|
|  `mylutece-oauth2.usePromptNone` | Enables redirection to the OAuth2 server to check if the user is already logged in with the prompt=true parameter| false|
|  `mylutece-oauth2.usePromptNoneWhiteListingHeaders` | Whitelist of HTTP headers (comma-separated) that disable the "use prompt none" flow (e.g. X-Requested-With for XMLHttpRequest requests)| X-Requested-With|
|  `mylutece-oauth2.usePromptNoneWhiteListingUrls` | Whitelist of URLs (comma-separated) that disable the "use prompt none" flow| empty|
Token Validation
| Parameter| Description| Default Value|
|-----------------|-----------------|-----------------|
|  `mylutece-oauth2.validateRefreshToken` | Validates the refresh token to check if the user is still logged in| false|
User Attributes
| Parameter| Description|
|-----------------|-----------------|
|  `mylutece-oauth2.attributeKeyUsername` | Attribute containing the Lutece username|
|  `mylutece-oauth2.attributeIdentityKey` | Attribute containing the identity key (optional)|
|  `mylutece-oauth2.userMappingAttributes` | List of attributes to map (comma-separated, optional). Example: user.name.given,user.name.family,user.business-info.soi,user.business-info.organizationUnit|

 **Note:** The `mylutece-oauth2.attribute.user.*` parameters allow you to map identity provider attributes with Lutece identity fields. These mappings are only documented here as a general concept.
DataClient Configuration
| Parameter| Description|
|-----------------|-----------------|
|  `mylutece-oauth2.dataclient.authData.dataServerUri` | URI of the OAuth2 server userinfo endpoint (e.g.: https://fcp.integ01.dev-franceconnect.fr/api/v1/userinfo)|
|  `mylutece-oauth2.dataclient.authData.tokenMethod` | Token transmission method (e.g.: HEADER)|
|  `mylutece-oauth2.dataclient.authData.scopes` | OAuth2 scopes requested (e.g.: openid,profile,email,address,phone)|
|  `mylutece-oauth2.dataclient.authData.default` | Indicates if this data client is the default one|
DataClient JSON Configuration
| Parameter| Description|
|-----------------|-----------------|
|  `mylutece-oauth2.dataclient.authDataJson.dataServerUri` | URI of the OAuth2 server userinfo endpoint for JSON version|
|  `mylutece-oauth2.dataclient.authDataJson.tokenMethod` | Token transmission method|
|  `mylutece-oauth2.dataclient.authDataJson.scopes` | OAuth2 scopes requested|
|  `mylutece-oauth2.dataclient.authDataJson.default` | Indicates if this data client is the default one|
Configuration Example
```

# Authentication Service
mylutece.url.login.page=servlet/plugins/oauth2/callback?data_client=authData
mylutece.url.doLogout=jsp/site/Portal.jsp?page=oauth2&action=dologout
mylutece-oauth2.service.name=Lutece Oauth2 Authentication Service
mylutece-oauth2.error.page=jsp/site/Portal.jsp?page=oauth2

# Prompt None
mylutece-oauth2.usePromptNone=false
mylutece-oauth2.usePromptNoneWhiteListingHeaders=X-Requested-With
mylutece-oauth2.usePromptNoneWhiteListingHeaders.X-Requested-With=XMLHttpRequest

# Token Validation
mylutece-oauth2.validateRefreshToken=false

# User Attributes
mylutece-oauth2.attributeKeyUsername=uid
mylutece-oauth2.attributeIdentityKey=
mylutece-oauth2.userMappingAttributes=user.name.given,user.name.family,user.business-info.soi,user.business-info.organizationUnit
mylutece-oauth2.attribute.user.name.given=prenom
mylutece-oauth2.attribute.user.name.family=nom

# DataClient Configuration
mylutece-oauth2.dataclient.authData.dataServerUri=https://fcp.integ01.dev-franceconnect.fr/api/v1/userinfo
mylutece-oauth2.dataclient.authData.tokenMethod=HEADER
mylutece-oauth2.dataclient.authData.scopes=openid,profile,email,address,phone
mylutece-oauth2.dataclient.authData.default=true

# DataClient JSON Configuration
mylutece-oauth2.dataclient.authDataJson.dataServerUri=https://fcp.integ01.dev-franceconnect.fr/api/v1/userinfo
mylutece-oauth2.dataclient.authDataJson.tokenMethod=HEADER
mylutece-oauth2.dataclient.authDataJson.scopes=openid,profile,email,address,phone
mylutece-oauth2.dataclient.authDataJson.default=false

```
Recommendations
 
*  **OAuth2 Scopes:** Adjust the scope list based on the information you need from the OAuth2 server
*  **Attribute Mapping:** Configure the `mylutece-oauth2.attribute.user.*` mappings according to the attribute structure provided by your OAuth2 server
*  **Prompt None:** Enable this feature with caution, as it can increase traffic to the OAuth2 server. Use whitelists to limit its impact
*  **DataClients:** You can configure multiple data clients (authData and authDataJson) to support different response formats from the OAuth2 server

## Usage

La page d'authentification FranceConnect s'appelle à partir de l'URL suivante :

 `http://myhost/lutece/jsp/site/Portal.jsp?page=franceconnect` 

Il est possible de réaliser ce formulaire d'authentification dans un portlet, soit en copiant le contenu du formulaire dans un portlet HTML, soit en modifiant la feuillede style XSL du portlet MyLutece.

## Dépannage


 
* Vérifiez bien la configuration de MyLutece comme indiqué ci-dessus.
* Assurez-vous que le module FranceConnect est le seul module MyLutece présent dans la Webapp. Il ne doit pas y avoir d'autres fichiers `mylutece-xxxxx.properties` dans le répertoire `WEB-INF/conf/plugins/` .
* Vérifiez bien la configuration du plugin FranceConnect.
* L'activation des logs en mode debug se fait en ajoutant la ligne suivante dans le fichier `WEB-INF/conf/config.properties` dans la rubrique LOGGERS :

```

log4j.logger.lutece.franceconnect=DEBUG, Console

```





[Maven documentation and reports](https://dev.lutece.paris.fr/plugins/module-mylutece-oauth2/)



 *generated by [xdoc2md](https://github.com/lutece-platform/tools-maven-xdoc2md-plugin) - do not edit directly.*