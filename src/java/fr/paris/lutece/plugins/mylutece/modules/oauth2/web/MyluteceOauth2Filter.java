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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.collections.map.HashedMap;
import org.apache.commons.lang.StringUtils;

import fr.paris.lutece.plugins.mylutece.modules.oauth2.authentication.AuthDataClient;
import fr.paris.lutece.plugins.mylutece.modules.oauth2.authentication.Oauth2Authentication;
import fr.paris.lutece.plugins.mylutece.modules.oauth2.authentication.Oauth2User;
import fr.paris.lutece.plugins.mylutece.modules.oauth2.service.Oauth2LuteceUserSessionService;
import fr.paris.lutece.plugins.oauth2.business.Token;
import fr.paris.lutece.plugins.oauth2.service.TokenService;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.security.SecurityService;
import fr.paris.lutece.portal.service.spring.SpringContextService;
import fr.paris.lutece.portal.service.util.AppPathService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import fr.paris.lutece.portal.web.PortalJspBean;
import fr.paris.lutece.util.url.UrlItem;

/**
 * ParisConnectLuteceFilters
 *
 */
public class MyluteceOauth2Filter implements Filter
{

    
 
    public static final String SESSION_MYLUTECE_OAUTH2_FILTER_ENABLE = "enable";
    public static final String PARAM_PROMPT_NONE = "prompt=none";
    
    private static final String PROPERTY_USE_PROMPT_NONE = "mylutece-oauth2.usePromptNone";
    private static final String PROPERTY_USE_PROMPT_NONE_WHITE_LISTING_URLS = "mylutece-oauth2.usePromptNoneWhiteListingUrls";
    private static final String PROPERTY_USE_PROMPT_NONE_WHITE_LISTING_HEADERS = "mylutece-oauth2.usePromptNoneWhiteListingHeaders";
    
    
    private static final String PROPERTY_VALIDATE_REFRESH_TOKEN = "mylutece-oauth2.validateRefreshToken";
     private static final String URL_INTERROGATIVE = "?";
    private static final String URL_AMPERSAND = "&";
    private static final String URL_EQUAL = "=";
    private static final String URL_STAR = "*";
    private static final String SEPARATOR = ",";
    
    private boolean _bUsePromptNone;
    private boolean _bValidateRefreshToken;
    private List<String> _listUsePromptWhiteUrls;
    private Map<String,List<String>> _mapUsePromptWhiteHeaders;
    
    
    
    
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

            if ( user == null && isUsePomptNoneForRequest(request) )
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
         
         String strTabWhiteListingUrls = AppPropertiesService.getProperty(PROPERTY_USE_PROMPT_NONE_WHITE_LISTING_URLS);
         String strTabWhiteListingHeaders = AppPropertiesService.getProperty(PROPERTY_USE_PROMPT_NONE_WHITE_LISTING_HEADERS);
			if (StringUtils.isNotBlank(strTabWhiteListingUrls)) {
				_listUsePromptWhiteUrls = Arrays.asList(strTabWhiteListingUrls.split(SEPARATOR));
			}
			if (StringUtils.isNotBlank(strTabWhiteListingHeaders)) {
				_mapUsePromptWhiteHeaders = new HashMap<String, List<String>>();
				Arrays.asList(strTabWhiteListingHeaders.split(SEPARATOR)).stream().forEach(x->_mapUsePromptWhiteHeaders.put(x, Arrays.asList(AppPropertiesService.getProperty(PROPERTY_USE_PROMPT_NONE_WHITE_LISTING_HEADERS+"."+x,"").split(SEPARATOR))));
			}
			
     }
    
    private boolean isUsePomptNoneForRequest(HttpServletRequest request)
    {
    	boolean bReturn=true;
    	if(_bUsePromptNone )
    	{
    	   //test headers white list	
    		if(_mapUsePromptWhiteHeaders!=null && _mapUsePromptWhiteHeaders.size()>0)
    		{
    			bReturn=!_mapUsePromptWhiteHeaders.keySet().stream().anyMatch(x-> request.getHeader(x)!=null && _mapUsePromptWhiteHeaders.get(x).stream().anyMatch(v->v.equalsIgnoreCase(request.getHeader(x))));
    			
    		}
    		//test url white List
    		if(bReturn && _listUsePromptWhiteUrls.size()>0)
    		{
    			bReturn=! _listUsePromptWhiteUrls.stream().anyMatch(x-> matchUrl(request, x));		
    		}
    				
    			
    	}
    	else
    	{
    		bReturn=false;
    	}
    	
    	return bReturn;
    	
    	
    }
    
    
    /**
     * method to test if the URL matches the pattern
    
     * @param request the request
     * @param strUrlPatern the pattern
     * @return true if the URL matches the pattern
     */
    private boolean matchUrl( HttpServletRequest request, String strUrlPatern )
    {
        boolean bMatch = false;

        if ( strUrlPatern != null )
        {
            UrlItem url = new UrlItem( getResquestedUrl( request ) );

            if ( strUrlPatern.contains( URL_INTERROGATIVE ) )
            {
                for ( String strParamPatternValue : strUrlPatern.substring( strUrlPatern.indexOf( URL_INTERROGATIVE ) +
                        1 ).split( URL_AMPERSAND ) )
                {
                    String[] arrayPatternParamValue = strParamPatternValue.split( URL_EQUAL );

                    if ( ( arrayPatternParamValue != null ) &&
                            ( request.getParameter( arrayPatternParamValue[0] ) != null ) )
                    {
                        url.addParameter( arrayPatternParamValue[0], request.getParameter( arrayPatternParamValue[0] ) );
                    }
                }
            }

            if ( strUrlPatern.contains( URL_STAR ) )
            {
                String strUrlPaternLeftEnd = strUrlPatern.substring( 0, strUrlPatern.indexOf( URL_STAR ) );
                String strAbsoluteUrlPattern = getAbsoluteUrl( request, strUrlPaternLeftEnd );
                bMatch = url.getUrl(  ).startsWith( strAbsoluteUrlPattern );
            }
            else
            {
                String strAbsoluteUrlPattern = getAbsoluteUrl( request, strUrlPatern );
                bMatch = url.getUrl(  ).equals( strAbsoluteUrlPattern );
            }
        }

        return bMatch;
    }
    
    /**
     * Returns the absolute url corresponding to the given one, if the later was
     * found to be relative. An url starting with "http://" is absolute. A
     * relative url should be given relatively to the webapp root.
     *
     * @param request
     *            the http request (provides the base path if needed)
     * @param strUrl
     *            the url to transform
     * @return the corresonding absolute url
     *
     * */
    private String getAbsoluteUrl( HttpServletRequest request, String strUrl )
    {
        if ( ( strUrl != null ) && !strUrl.startsWith( "http://" ) && !strUrl.startsWith( "https://" ) )
        {
            return AppPathService.getBaseUrl( request ) + strUrl;
        }
        else
        {
            return strUrl;
        }
    }

    /**
     * Return the absolute representation of the requested url
     *
     * @param request
     *            the http request (provides the base path if needed)
     * @return the requested url has a string
     *
     * */
    private String getResquestedUrl( HttpServletRequest request )
    {
        return AppPathService.getBaseUrl( request ) + request.getServletPath(  ).substring( 1 );
    }



   

}
