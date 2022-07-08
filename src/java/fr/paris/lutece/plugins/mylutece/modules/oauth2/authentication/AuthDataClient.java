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
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import fr.paris.lutece.plugins.mylutece.modules.oauth2.service.Oauth2Service;
import fr.paris.lutece.plugins.mylutece.web.MyLuteceApp;
import fr.paris.lutece.plugins.oauth2.business.Token;
import fr.paris.lutece.plugins.oauth2.dataclient.AbstractDataClient;
import fr.paris.lutece.plugins.oauth2.web.Constants;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPathService;
import fr.paris.lutece.portal.web.PortalJspBean;

/**
 * UserInfoDataClient
 */
public class AuthDataClient extends AbstractDataClient
{

    public static final String ERROR_TYPE_LOGIN_REQUIRED = "login_required";
    public static final String REINIT_ERROR_LOGIN = "reinit_error_login";
    public static final String SESSION_ERROR_LOGIN = "session_error_login";
    public static final String PARAM_ERROR_LOGIN = "error_login";
    public static final String PARAM_NEXT_URL = "next_url";
    private static ObjectMapper _mapper;

    static
    {
        _mapper = new ObjectMapper( );
        _mapper.disable( DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES );
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public void handleToken( Token token, HttpServletRequest request, HttpServletResponse response )
    {
        try
        {
            Map<String, Object> mapUserInfo = parse( getData( token ) );
            Oauth2Service.getInstance( ).processAuthentication( request, mapUserInfo, token );
            Oauth2Service.redirect( request, response );

        }
        catch( IOException ex )
        {
            _logger.error( "Error parsing UserInfo ", ex );
        }
    }

    /**
     * parse the JSON for a token
     * 
     * @param strJson
     *            The JSON
     * @return The UserInfo
     * @throws java.io.IOException
     *             if an error occurs
     */
    Map<String, Object> parse( String strJson ) throws IOException
    {
        TypeReference<HashMap<String, Object>> typeRef = new TypeReference<HashMap<String, Object>>( )
        {
        };

        return _mapper.readValue( strJson, typeRef );
    }

    @Override
    public void handleError( HttpServletRequest request, HttpServletResponse response, String strError )
    {

        HttpSession session = request.getSession( true );
      

        if ( AuthDataClient.ERROR_TYPE_LOGIN_REQUIRED.equals( strError ) )
        {

            try
            {

                String strLoginNextUrl = PortalJspBean.getLoginNextUrl( request );
                // if the is not next url in session get default next Url
                if ( strLoginNextUrl == null )
                {
                    strLoginNextUrl = AppPathService.getAbsoluteUrl( request, AppPathService.getRootForwardUrl( ) );
                }
                strLoginNextUrl = response.encodeRedirectURL( strLoginNextUrl );
                // if SESSION_ERROR_LOGIN attribute is not store in session added this information in the redirect url
                if ( strLoginNextUrl != null && session.getAttribute( AuthDataClient.SESSION_ERROR_LOGIN ) == null )
                {
                    if ( strLoginNextUrl.contains( "?" ) )
                    {
                        strLoginNextUrl += "&";
                    }
                    else
                    {
                        strLoginNextUrl += "?";

                    }
                    strLoginNextUrl += AuthDataClient.PARAM_ERROR_LOGIN + "=" + AuthDataClient.ERROR_TYPE_LOGIN_REQUIRED;
                }
                
                session.setAttribute( SESSION_ERROR_LOGIN, strError );
                response.sendRedirect( strLoginNextUrl );
            }
            catch( IOException e )
            {
                AppLogService.error( "Oauth 2 error", e );
            }

        }
        else
        {
            try
            {

                if ( Constants.ERROR_TYPE_INVALID_STATE.equals( strError ) || Constants.ERROR_TYPE_RETRIEVING_AUTHORIZATION_CODE.equals( strError ) )
                {
                    AppLogService.info( "Oauth 2 error  " + strError + " redirect on default url" );
                }
                else
                {
                    AppLogService.error( "Oauth 2 error  " + strError + " redirect on default url" );
                }

                response.sendRedirect( AppPathService.getAbsoluteUrl( request, AppPathService.getRootForwardUrl( ) ) );
            }
            catch( IOException e )
            {
                AppLogService.error( "Oauth 2 error", e );
            }
        }
    }

}
