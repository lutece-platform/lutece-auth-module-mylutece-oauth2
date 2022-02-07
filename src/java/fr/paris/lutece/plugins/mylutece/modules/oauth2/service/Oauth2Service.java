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
package fr.paris.lutece.plugins.mylutece.modules.oauth2.service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;

import fr.paris.lutece.plugins.mylutece.authentication.MultiLuteceAuthentication;
import fr.paris.lutece.plugins.mylutece.business.LuteceUserAttributeDescription;
import fr.paris.lutece.plugins.mylutece.modules.oauth2.authentication.Oauth2Authentication;
import fr.paris.lutece.plugins.mylutece.modules.oauth2.authentication.Oauth2User;
import fr.paris.lutece.plugins.mylutece.service.MyLuteceUserService;
import fr.paris.lutece.plugins.mylutece.web.MyLuteceApp;
import fr.paris.lutece.plugins.oauth2.business.Token;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.security.SecurityService;
import fr.paris.lutece.portal.service.spring.SpringContextService;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import fr.paris.lutece.portal.web.PortalJspBean;

// TODO: Auto-generated Javadoc
/**
 * France Connect Service.
 */
public final class Oauth2Service
{

    /** The Constant _authService. */
    private static  Oauth2Authentication _authService ;

    /** The logger. */
    private static Logger _logger = Logger.getLogger( "lutece.oauth2" );

    /** The Constant AUTHENTICATION_BEAN_NAME. */
    private static final String AUTHENTICATION_BEAN_NAME = "mylutece-oauth2.authentication";
    
    /** The Constant PROPERTY_USER_KEY_NAME. */
    private static final String PROPERTY_USER_KEY_NAME = "mylutece-oauth2.attributeKeyUsername";

    /** The Constant PROPERTY_USER_MAPPING_ATTRIBUTES. */
    private static final String PROPERTY_USER_MAPPING_ATTRIBUTES = "mylutece-oauth2.userMappingAttributes";

    /** The Constant PROPERTY_IDENTITY_ATTRIBUTE_KEY. */
    private static final String PROPERTY_IDENTITY_ATTRIBUTE_KEY = "mylutece-oauth2.attributeIdentityKey";

    /** The Constant TOKEN_SUBJECT. */
    private static final String TOKEN_SUBJECT = "sub";

    /** The Constant CONSTANT_LUTECE_USER_PROPERTIES_PATH. */
    private static final String CONSTANT_LUTECE_USER_PROPERTIES_PATH = "mylutece-oauth2.attribute";

    /** The attribute user mapping. */
    private static Map<String, List<String>> ATTRIBUTE_USER_MAPPING;

    /** The attribute user key name. */
    private static String [ ] ATTRIBUTE_USER_KEY_NAME;

    /** The Constant SEPARATOR. */
    private static final String SEPARATOR = ",";

    /** The singleton. */
    private static Oauth2Service _singleton;

    /**
     * private constructor.
     */
    private Oauth2Service( )
    {
    }

    /**
     * Gets the instance.
     *
     * @return the instance
     */
    public static Oauth2Service getInstance( )
    {
        if ( _singleton == null )
        {

            _singleton = new Oauth2Service( );
            String strTabUserKey = AppPropertiesService.getProperty( PROPERTY_USER_KEY_NAME );
            if ( StringUtils.isNotBlank( strTabUserKey ) )
            {
                ATTRIBUTE_USER_KEY_NAME = strTabUserKey.split( SEPARATOR );
            }
            String strUserMappingAttributes = AppPropertiesService.getProperty( PROPERTY_USER_MAPPING_ATTRIBUTES );
            ATTRIBUTE_USER_MAPPING = new HashMap<String, List<String>>( );

            if ( StringUtils.isNotBlank( strUserMappingAttributes ) )
            {
                String [ ] tabUserProperties = strUserMappingAttributes.split( SEPARATOR );
                String [ ] tabPropertiesValues;
                String userProperties;

                for ( int i = 0; i < tabUserProperties.length; i++ )
                {
                    userProperties = AppPropertiesService.getProperty( CONSTANT_LUTECE_USER_PROPERTIES_PATH + "." + tabUserProperties [i] );

                    if ( StringUtils.isNotBlank( userProperties ) )
                    {

                        if ( userProperties.contains( SEPARATOR ) )
                        {
                            tabPropertiesValues = userProperties.split( SEPARATOR );

                            for ( int n = 0; i < tabPropertiesValues.length; n++ )
                            {
                                if ( !ATTRIBUTE_USER_MAPPING.containsKey( tabPropertiesValues [n] ) )
                                {
                                    ATTRIBUTE_USER_MAPPING.put( tabPropertiesValues [n], new ArrayList<String>( ) );
                                }
                                ATTRIBUTE_USER_MAPPING.get( tabPropertiesValues [n] ).add( tabUserProperties [i] );
                            }

                        }
                        else
                        {

                            if ( !ATTRIBUTE_USER_MAPPING.containsKey( userProperties ) )
                            {
                                ATTRIBUTE_USER_MAPPING.put( userProperties, new ArrayList<String>( ) );
                            }
                            ATTRIBUTE_USER_MAPPING.get( userProperties ).add( tabUserProperties [i] );
                        }

                    }
                }
            }
        }

        return _singleton;
    }

    /**
     * Process the authentication.
     *
     * @param request
     *            The HTTP request
     * @param mapUserInfo
     *            the map user info
     * @param token
     *            the token
     * @return the oauth 2 user
     */
    public Oauth2User processAuthentication( HttpServletRequest request, Map<String, Object> mapUserInfo, Token token )
    {

        // subject in user map
        if ( token.getIdToken( ) != null && token.getIdToken( ).getSubject( ) != null )
        {
            mapUserInfo.put( TOKEN_SUBJECT, token.getIdToken( ).getSubject( ) );

        }
        Oauth2User user = null;
        for ( int i = 0; i < ATTRIBUTE_USER_KEY_NAME.length; i++ )
        {

            if ( mapUserInfo.containsKey( ATTRIBUTE_USER_KEY_NAME [i] ) )
            {
                user = new Oauth2User( (String) mapUserInfo.get( ATTRIBUTE_USER_KEY_NAME [i] ), token, _authService );
            }
        }

        if ( user != null )
        {

            for ( Entry<String, Object> entry : mapUserInfo.entrySet( ) )
            {
                if ( ATTRIBUTE_USER_MAPPING.containsKey( entry.getKey( ) ) )
                {
                    for ( String strUserInfo : ATTRIBUTE_USER_MAPPING.get( entry.getKey( ) ) )
                    {

                        Object val = entry.getValue( );
                        if ( val instanceof ArrayList<?> )
                        {

                            StringBuffer strBufVal = new StringBuffer( );
                            for ( String tabVal : (ArrayList<String>) val )
                            {
                                strBufVal.append( tabVal );
                                strBufVal.append( SEPARATOR );
                            }
                            if ( strBufVal.length( ) > 0 )
                            {
                                user.setUserInfo( strUserInfo, strBufVal.substring( 0, strBufVal.length( ) - 1 ) );
                            }

                            user.setUserInfo( strUserInfo, strBufVal.toString( ) );

                        }
                        else
                        {
                            user.setUserInfo( strUserInfo, (String) val );

                        }
                    }
                }
                // set Email in lutece User
                if ( !StringUtils.isEmpty( user.getUserInfo( LuteceUser.HOME_INFO_ONLINE_EMAIL ) ) )
                {
                    user.setEmail( user.getUserInfo( LuteceUser.HOME_INFO_ONLINE_EMAIL ) );

                }
                else
                    if ( !StringUtils.isEmpty( user.getUserInfo( LuteceUser.BUSINESS_INFO_ONLINE_EMAIL ) ) )
                    {
                        user.setEmail( user.getUserInfo( LuteceUser.BUSINESS_INFO_ONLINE_EMAIL ) );

                    }

            }

            // add Identities Informations
            // get Identity key the default key is the value of lutece user name
            String strIdentityKey = user.getName( );
            String strIdentityKeyAttribute = AppPropertiesService.getProperty( PROPERTY_IDENTITY_ATTRIBUTE_KEY );
            if ( strIdentityKeyAttribute != null && mapUserInfo.containsKey( strIdentityKeyAttribute ) )
            {
                strIdentityKey = mapUserInfo.get( strIdentityKeyAttribute ).toString( );
            }

            user.setName( strIdentityKey );
            MyLuteceUserService.provideUserExternalInfos( user );

            // add Oauth2LuteceUserSessionService session
            Oauth2LuteceUserSessionService.getInstance( ).addLuteceUserSession( user.getName( ), request.getSession( true ).getId( ) );

        }

        SecurityService.getInstance( ).registerUser( request, user );

        return user;
    }
    
    /**
     * Inits the service
     */
    public void init()
    {
    	
     	//register Authentication
     	 _authService = SpringContextService.getBean( AUTHENTICATION_BEAN_NAME );

         if ( _authService != null )
         {
             MultiLuteceAuthentication.registerAuthentication( _authService );
         }
         else
         {
             AppLogService.error( "Mylutece  Ouath2 Authentication not found, please check your mylutece-oauth2_context.xml configuration" );
         }
    	
    }
    
    /**
     * 
     * @return the Lutece user Attribute provided by the authentication module
     */
    public List<LuteceUserAttributeDescription> getLuteceUserAttributesProvided(Locale locale)
    {
    	
    	List<LuteceUserAttributeDescription> listUserDescription=  new ArrayList<LuteceUserAttributeDescription>();
    
    	
    	String strUserMappingAttributes = AppPropertiesService.getProperty( PROPERTY_USER_MAPPING_ATTRIBUTES );
        ATTRIBUTE_USER_MAPPING = new HashMap<String, List<String>>( );

        if ( StringUtils.isNotBlank( strUserMappingAttributes ) )
        {
            String [ ] tabUserProperties = strUserMappingAttributes.split( SEPARATOR );
            
            for ( int i = 0; i < tabUserProperties.length; i++ )
            {
                 
                  listUserDescription.add(new LuteceUserAttributeDescription( tabUserProperties [i],  AppPropertiesService.getProperty( CONSTANT_LUTECE_USER_PROPERTIES_PATH + "." + tabUserProperties [i] ) , ""));
            }
        }
    	
         	
        return listUserDescription;
    }

    /**
     * Process the logout.
     *
     * @param request
     *            The HTTP request
     */
    public static void processLogout( HttpServletRequest request )
    {
        _logger.debug( "Process logout" );
        SecurityService.getInstance( ).logoutUser( request );
    }

    /**
     * redirect after login or logout.
     *
     * @param request
     *            The HTTP request
     * @param response
     *            The HTTP response
     * @throws IOException
     *             if an error occurs
     */
    public static void redirect( HttpServletRequest request, HttpServletResponse response ) throws IOException
    {
        String strNextURL = PortalJspBean.getLoginNextUrl( request );
        _logger.info( "Next URL : " + strNextURL );

        if ( strNextURL == null )
        {
            strNextURL = MyLuteceApp.getDefaultRedirectUrl( );
        }

        strNextURL = response.encodeRedirectURL( strNextURL );

        response.sendRedirect( strNextURL );
    }
    
   
    
    
    

}
