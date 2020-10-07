/*
 * Copyright (c) 2002-2014, Mairie de Paris
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
package fr.paris.lutece.plugins.mylutece.modules.oauth2.web;

import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import fr.paris.lutece.plugins.mylutece.modules.oauth2.authentication.AuthDataClient;
import fr.paris.lutece.plugins.mylutece.modules.oauth2.authentication.Oauth2Authentication;
import fr.paris.lutece.plugins.mylutece.modules.oauth2.authentication.Oauth2User;
import fr.paris.lutece.plugins.mylutece.modules.oauth2.service.Oauth2LuteceUserSessionService;
import fr.paris.lutece.plugins.oauth2.business.Token;
import fr.paris.lutece.plugins.oauth2.service.TokenService;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.security.SecurityService;
import fr.paris.lutece.portal.service.spring.SpringContextService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import fr.paris.lutece.portal.web.PortalJspBean;

/**
 * ParisConnectLuteceFilters
 *
 */
public class MyluteceOauth2Filter implements Filter
{

    
 
    public static final String SESSION_MYLUTECE_OAUTH2_FILTER_ENABLE = "enable";
    public static final String PARAM_PROMPT_NONE = "prompt=none";
    
    private static final String PROPERTY_USE_PROMPT_NONE = "mylutece-oauth2.usePromptNone";
    private static final String PROPERTY_VALIDATE_REFRESH_TOKEN = "mylutece-oauth2.validateRefreshToken";
    
    
    private boolean _bUsePromptNone;
    private boolean _bValidateRefreshToken;
    
    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void destroy( )
    {
        // nothing
    }

    /**
     *
     * {@inheritDoc}
     */
    @SuppressWarnings( "deprecation" )
    @Override
    public void doFilter( ServletRequest servletRequest, ServletResponse response, FilterChain chain ) throws IOException, ServletException
    {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse resp = (HttpServletResponse) response;
        if ( request != null && "GET".equals( request.getMethod( ) ) )
        {
            LuteceUser user = SecurityService.getInstance( ).getRegisteredUser( request );

            if ( user == null && _bUsePromptNone )
            {
                HttpSession session = request.getSession( true );

                if ( ( session.getAttribute( AuthDataClient.SESSION_ERROR_LOGIN ) == null && request.getParameter( AuthDataClient.PARAM_ERROR_LOGIN ) == null )
                        || session.getAttribute( AuthDataClient.SESSION_ERROR_LOGIN ) != null
                                && session.getAttribute( AuthDataClient.SESSION_ERROR_LOGIN ).equals( AuthDataClient.REINIT_ERROR_LOGIN ) )
                {
                    session.setAttribute( AuthDataClient.SESSION_ERROR_LOGIN, AuthDataClient.REINIT_ERROR_LOGIN );
                    String strRedirectLoginUrl = PortalJspBean.redirectLogin( request );
                    resp.sendRedirect( strRedirectLoginUrl + "&" + "complementary_parameter=" + URLEncoder.encode( PARAM_PROMPT_NONE ) );
                    return;
                }

                session.setAttribute( AuthDataClient.SESSION_ERROR_LOGIN, AuthDataClient.REINIT_ERROR_LOGIN );
            }
            else if(_bValidateRefreshToken && user instanceof Oauth2User)
            {
                Oauth2User oauth2User=(Oauth2User)user;
                if(oauth2User.getToken( )!=null && oauth2User.getToken( ).getRefreshToken( ) !=null )
                {
                	Token token=TokenService.getService( ).getTokenByRefreshToken(oauth2User.getToken( ).getRefreshToken( ) ) ;
                	if(token==null)
                	{
                   
                                SecurityService.getInstance().logoutUser(request);
                	}
                	else
                	{
                		oauth2User.setToken(token);
                	}
                }
            }
          if( !Oauth2LuteceUserSessionService.getInstance(  )
            .isLuteceUserUpToDate( request.getSession( true ).getId(  ) ))
            {
                
                Oauth2Authentication oauth2Authentication = (Oauth2Authentication) SpringContextService.getBean( 
                        "mylutece-oauth2.authentication" );
                user = oauth2Authentication.getHttpAuthenticatedUser( request );
                
                if ( user != null )
                {
                    SecurityService.getInstance(  ).registerUser( request, user );
                }
                
            }

        }

        chain.doFilter( servletRequest, response );
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void init( FilterConfig config ) throws ServletException
    {
         _bUsePromptNone=AppPropertiesService.getPropertyBoolean( PROPERTY_USE_PROMPT_NONE, false );
         _bValidateRefreshToken=AppPropertiesService.getPropertyBoolean( PROPERTY_VALIDATE_REFRESH_TOKEN, false );
         
    }


   

}
