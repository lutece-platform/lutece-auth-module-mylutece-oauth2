/*
 * Copyright (c) 2002-2017, Mairie de Paris
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

import fr.paris.lutece.plugins.mylutece.authentication.PortalAuthentication;
import fr.paris.lutece.portal.service.security.LoginRedirectException;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.util.AppPropertiesService;

import java.io.Serializable;

import javax.security.auth.login.LoginException;

import javax.servlet.http.HttpServletRequest;


/**
 * The Class provides an implementation of the inherited abstract class
 * PortalAuthentication based on OpenID
 */
public class Oauth2Authentication extends PortalAuthentication implements Serializable
{
    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Constants
    private static final String PROPERTY_AUTH_SERVICE_NAME = "mylutece-franceconnect.service.name";
    private static final String CONSTANT_PATH_ICON = "images/local/skin/plugins/mylutece/modules/openid/mylutece-openid.png";
    private static final String PLUGIN_NAME = "mylutece-openid";
    private static final long serialVersionUID = 1L;

    /**
     * Gets the Authentification service name
     *
     * @return The name of the authentication service
     */
    @Override
    public String getAuthServiceName(  )
    {
        return AppPropertiesService.getProperty( PROPERTY_AUTH_SERVICE_NAME );
    }

    /**
     * Gets the Authentification type
     *
     * @param request The HTTP request
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
     * @param strUserName The username
     * @param strUserPassword The password
     * @param request The HttpServletRequest
     * @throws LoginRedirectException This exception is used to redirect the
     * authentication to the provider
     * @throws LoginException The LoginException
     */
    @Override
    public LuteceUser login( String strUserName, String strUserPassword, HttpServletRequest request )
        throws LoginException, LoginRedirectException
    {
        return getHttpAuthenticatedUser( request );
    }

    /**
     * This methods logout the user
     *
     * @param user The user
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
    public LuteceUser getAnonymousUser(  )
    {
        return new Oauth2User( LuteceUser.ANONYMOUS_USERNAME, this );
    }

    /**
     * Checks that the current user is associated to a given role
     *
     * @param user The user
     * @param request The HTTP request
     * @param strRole The role name
     * @return Returns true if the user is associated to the role, otherwise
     * false
     */
    @Override
    public boolean isUserInRole( LuteceUser user, HttpServletRequest request, String strRole )
    {
        // Not used
        return false;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public String getIconUrl(  )
    {
        return CONSTANT_PATH_ICON;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public String getName(  )
    {
        return PLUGIN_NAME;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public String getPluginName(  )
    {
        return PLUGIN_NAME;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean isMultiAuthenticationSupported(  )
    {
        return false;
    }
}
