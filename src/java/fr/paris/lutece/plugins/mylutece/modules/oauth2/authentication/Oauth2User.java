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

import fr.paris.lutece.plugins.oauth2.business.Token;
import fr.paris.lutece.portal.service.security.LuteceAuthentication;
import fr.paris.lutece.portal.service.security.LuteceUser;

import java.io.Serializable;


// TODO: Auto-generated Javadoc
/**
 * This class implements The Lutece User in a OpenID configuration.
 */
public class Oauth2User extends LuteceUser implements Serializable
{
    
    /** The Constant ACCESS_TOKEN. */
    public static final String ACCESS_TOKEN = "oauth2.user.accessToken";

    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 1L;
    
    /** The str email. */
    private String _strEmail;
    
    /** The token. */
    private Token _token;


    

    /**
     * Constructor.
     *
     * @param strUserName The user's name
     * @param token the token
     * @param authenticationService The authentication service that authenticates the user
     */
    public Oauth2User( String strUserName,Token token, LuteceAuthentication authenticationService )
    {
        super( strUserName, authenticationService );
        this.setLuteceAuthenticationService( authenticationService );
        this._token=token;
    }

    /**
     * {@inheritDoc }.
     *
     * @return the email
     */
    @Override
    public String getEmail(  )
    {
        return ( _strEmail != null ) ? _strEmail : "";
    }

   

    /**
     * Sets the Email.
     *
     * @param strEmail         The Email
     */
    public void setEmail( String strEmail )
    {
        _strEmail = strEmail;
    }
    
    
    /**
     * Gets the token.
     *
     * @return the token
     */
    public Token getToken( )
    {
        return _token;
    }
    
    /**
     * Sets the token.
     *
     * @param token the new token
     */
    public void setToken(Token token )
    {
       _token=token;
    }


  
}
