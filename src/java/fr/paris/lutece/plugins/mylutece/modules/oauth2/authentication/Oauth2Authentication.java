/*
 * Copyright (c) 2002-2021, City of Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */
package fr.paris.lutece.plugins.mylutece.modules.oauth2.authentication;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;

import fr.paris.lutece.plugins.mylutece.authentication.PortalAuthentication;
import fr.paris.lutece.plugins.mylutece.business.LuteceUserAttributeDescription;
import fr.paris.lutece.plugins.mylutece.business.LuteceUserRoleDescription;
import fr.paris.lutece.plugins.mylutece.business.attribute.AttributeHome;
import fr.paris.lutece.plugins.mylutece.modules.oauth2.service.Oauth2Service;
import fr.paris.lutece.plugins.mylutece.service.MyLutecePlugin;
import fr.paris.lutece.plugins.oauth2.business.Token;
import fr.paris.lutece.plugins.oauth2.service.DataClientService;
import fr.paris.lutece.plugins.oauth2.service.TokenService;
import fr.paris.lutece.portal.business.role.RoleHome;
import fr.paris.lutece.portal.service.plugin.Plugin;
import fr.paris.lutece.portal.service.plugin.PluginService;
import fr.paris.lutece.portal.service.security.LoginRedirectException;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.security.SecurityService;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;

/**
 * The Class provides an implementation of the inherited abstract class PortalAuthentication based on OpenID
 */
public class Oauth2Authentication extends PortalAuthentication implements Serializable
{
    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Constants
    private static final String PROPERTY_AUTH_SERVICE_NAME = "mylutece-oauth2.service.name";
    private static final String CONSTANT_PATH_ICON = "images/local/skin/plugins/mylutece/modules/openid/mylutece-openid.png";
    private static final String PLUGIN_NAME = "mylutece-oauth2";
    private static final long serialVersionUID = 1L;
    private static final String authDataClientName = "authData";

    /**
     * Gets the Authentification service name
     *
     * @return The name of the authentication service
     */
    @Override
    public String getAuthServiceName( )
    {
        return AppPropertiesService.getProperty( PROPERTY_AUTH_SERVICE_NAME );
    }

    /**
     * Gets the Authentification type
     *
     * @param request
     *            The HTTP request
     * @return The type of authentication
     */
    @Override
    public String getAuthType( HttpServletRequest request )
    {
        return HttpServletRequest.BASIC_AUTH;
    }

    /**
     * This methods checks the login info in the LDAP repository
     *
     *
     * @return A LuteceUser object corresponding to the login
     * @param strUserName
     *            The username
     * @param strUserPassword
     *            The password
     * @param request
     *            The HttpServletRequest
     * @throws LoginRedirectException
     *             This exception is used to redirect the authentication to the provider
     * @throws LoginException
     *             The LoginException
     */
    @Override
    public LuteceUser processLogin( String strUserName, String strUserPassword, HttpServletRequest request ) throws LoginException, LoginRedirectException
    {
        return getHttpAuthenticatedUser( request );
    }

    /**
     * This methods logout the user
     *
     * @param user
     *            The user
     */
    @Override
    public void logout( LuteceUser user )
    {
    }

    /**
     * This method returns an anonymous Lutece user
     *
     * @return An anonymous Lutece user
     */
    @Override
    public LuteceUser getAnonymousUser( )
    {
        return new Oauth2User( LuteceUser.ANONYMOUS_USERNAME, null, this );
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public String getIconUrl( )
    {
        return CONSTANT_PATH_ICON;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public String getName( )
    {
        return PLUGIN_NAME;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public String getPluginName( )
    {
        return PLUGIN_NAME;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean isMultiAuthenticationSupported( )
    {
        return false;
    }

    /**
     * Returns a Lutece user object if the user is already authenticated by Openam
     * 
     * @param request
     *            The HTTP request
     * @return Returns A Lutece User or null if there no user authenticated
     */
    @Override
    public LuteceUser getHttpAuthenticatedUser( HttpServletRequest request )
    {
        LuteceUser user = null;
        user = SecurityService.getInstance( ).getRegisteredUser( request );
        // Reload User if info
        if ( user != null && user instanceof Oauth2User )
        {
            Oauth2User userOauth = (Oauth2User) user;
            if ( userOauth.getToken( ).getRefreshToken( ) != null )
            {

                AuthDataClient authDataClient = (AuthDataClient) DataClientService.instance( ).getClient( authDataClientName );
                Token token = TokenService.getService( ).getTokenByRefreshToken( userOauth.getToken( ).getRefreshToken( ) );
                try
                {
                    Map<String, Object> mapUserInfo = authDataClient.parse( authDataClient.getData( token ) );
                    return Oauth2Service.getInstance( ).processAuthentication( request, mapUserInfo, token );

                }
                catch( IOException e )
                {
                    // TODO Auto-generated catch block
                    AppLogService.error( "error during retrieving user info with refresh token  ", e );
                }

            }
            // userOauth.getToken( )
            // // add Openam LuteceUser session
            // OpenamLuteceUserSessionService.getInstance( ).addLuteceUserSession( user.getName( ), request.getSession( true ).getId( ) );
            // }
        }

        return user;
    }
    
    
    

    /**
     * {@inheritDoc}
     */
    @Override
   public List<LuteceUserAttributeDescription> getLuteceUserAttributesProvided(Locale locale)
    {
    	
    	return Oauth2Service.getInstance().getLuteceUserAttributesProvided(locale);
    }
}
