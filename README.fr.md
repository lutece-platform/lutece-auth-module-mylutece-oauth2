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

Les paramètres de configuration du module sont gérés dans le fichier `WEB-INF/conf/plugins/mylutece-oauth2.properties` .
Service d'Authentification
| Paramètre| Description| Valeur par défaut|
|-----------------|-----------------|-----------------|
|  `mylutece.url.login.page` | Page de connexion du service OAuth2| servlet/plugins/oauth2/callback?data_client=authData|
|  `mylutece.url.doLogout` | Page de déconnexion| jsp/site/Portal.jsp?page=oauth2&action=dologout|
|  `mylutece-oauth2.service.name` | Nom du service d'authentification| Lutece Oauth2 Authentication Service|
|  `mylutece-oauth2.error.page` | Page de gestion des erreurs| jsp/site/Portal.jsp?page=oauth2|
Gestion du Prompt None
| Paramètre| Description| Valeur par défaut|
|-----------------|-----------------|-----------------|
|  `mylutece-oauth2.usePromptNone` | Active la redirection vers le serveur OAuth2 pour vérifier si l'utilisateur est déjà connecté avec le paramètre prompt=true| false|
|  `mylutece-oauth2.usePromptNoneWhiteListingHeaders` | Liste blanche des en-têtes HTTP (séparés par des virgules) qui désactivent le flux "use prompt none" (ex: X-Requested-With pour les requêtes XMLHttpRequest)| X-Requested-With|
|  `mylutece-oauth2.usePromptNoneWhiteListingUrls` | Liste blanche des URLs (séparées par des virgules) qui désactivent le flux "use prompt none"| vide|
Validation des Tokens
| Paramètre| Description| Valeur par défaut|
|-----------------|-----------------|-----------------|
|  `mylutece-oauth2.validateRefreshToken` | Valide le refresh token pour vérifier si l'utilisateur est toujours connecté| false|
Attributs Utilisateur
| Paramètre| Description|
|-----------------|-----------------|
|  `mylutece-oauth2.attributeKeyUsername` | Attribut contenant le nom d'utilisateur Lutece|
|  `mylutece-oauth2.attributeIdentityKey` | Attribut contenant la clé d'identité (optionnel)|
|  `mylutece-oauth2.userMappingAttributes` | Liste des attributs à mapper (séparés par des virgules, optionnel). Exemple: user.name.given,user.name.family,user.business-info.soi,user.business-info.organizationUnit|

 **Note :** Les paramètres `mylutece-oauth2.attribute.user.*` permettent de mapper les attributs du fournisseur d'identités avec les champs d'identité de Lutece. Ces mappages ne sont documentés ici que comme concept général.
Configuration DataClient
| Paramètre| Description|
|-----------------|-----------------|
|  `mylutece-oauth2.dataclient.authData.dataServerUri` | URI du endpoint userinfo du serveur OAuth2 (ex: https://fcp.integ01.dev-franceconnect.fr/api/v1/userinfo)|
|  `mylutece-oauth2.dataclient.authData.tokenMethod` | Méthode de transmission du token (ex: HEADER)|
|  `mylutece-oauth2.dataclient.authData.scopes` | Scopes OAuth2 demandés (ex: openid,profile,email,address,phone)|
|  `mylutece-oauth2.dataclient.authData.default` | Indique si ce client de données est le client par défaut|
Configuration DataClient JSON
| Paramètre| Description|
|-----------------|-----------------|
|  `mylutece-oauth2.dataclient.authDataJson.dataServerUri` | URI du endpoint userinfo du serveur OAuth2 pour la version JSON|
|  `mylutece-oauth2.dataclient.authDataJson.tokenMethod` | Méthode de transmission du token|
|  `mylutece-oauth2.dataclient.authDataJson.scopes` | Scopes OAuth2 demandés|
|  `mylutece-oauth2.dataclient.authDataJson.default` | Indique si ce client de données est le client par défaut|
Exemple de Configuration
```

# Service d'Authentification
mylutece.url.login.page=servlet/plugins/oauth2/callback?data_client=authData
mylutece.url.doLogout=jsp/site/Portal.jsp?page=oauth2&action=dologout
mylutece-oauth2.service.name=Lutece Oauth2 Authentication Service
mylutece-oauth2.error.page=jsp/site/Portal.jsp?page=oauth2

# Prompt None
mylutece-oauth2.usePromptNone=false
mylutece-oauth2.usePromptNoneWhiteListingHeaders=X-Requested-With
mylutece-oauth2.usePromptNoneWhiteListingHeaders.X-Requested-With=XMLHttpRequest

# Validation Tokens
mylutece-oauth2.validateRefreshToken=true

# Attributs Utilisateur
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
Recommandations
 
*  **Scopes OAuth2 :** Ajustez la liste des scopes en fonction des informations dont vous avez besoin du serveur OAuth2
*  **Mapping d'Attributs :** Configurez les mappages `mylutece-oauth2.attribute.user.*` selon la structure des attributs fournis par votre serveur OAuth2
*  **Prompt None :** Activez cette fonctionnalité avec prudence, car elle peut augmenter le trafic vers le serveur OAuth2. Utilisez les listes blanches pour limiter son impact
*  **DataClients :** Vous pouvez configurer plusieurs clients de données (authData et authDataJson) pour supporter différents formats de réponse du serveur OAuth2

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