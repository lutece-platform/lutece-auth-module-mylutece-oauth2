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
package fr.paris.lutece.plugins.mylutece.modules.oauth2.web;

import fr.paris.lutece.plugins.mylutece.modules.oauth2.authentication.Oauth2User;
import fr.paris.lutece.plugins.mylutece.web.MyLuteceApp;
import fr.paris.lutece.plugins.oauth2.business.Token;
import fr.paris.lutece.plugins.oauth2.service.TokenService;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.security.SecurityService;
import fr.paris.lutece.portal.service.util.AppPathService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import fr.paris.lutece.portal.util.mvc.commons.annotations.Action;
import fr.paris.lutece.portal.util.mvc.commons.annotations.View;
import fr.paris.lutece.portal.util.mvc.xpage.MVCApplication;
import fr.paris.lutece.portal.util.mvc.xpage.annotations.Controller;
import fr.paris.lutece.portal.web.xpages.XPage;
import fr.paris.lutece.util.url.UrlItem;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

/**
 * France Connect XPage Application
 */
@Controller( xpageName = "Oauth2", pagePathI18nKey = "module.mylutece.oauth2.loginPagePath", pageTitleI18nKey = "module.mylutece.oauth2.loginPageTitle" )
public class Oauth2App extends MVCApplication
{
    // Views
    private static final String VIEW_HOME = "home";

    // Templates
    private static final String TEMPLATE_LOGIN_PAGE = "skin/plugins/mylutece/modules/oauth2/login_form.html";

    // Markers
    private static final String MARK_USER = "user";
    private static final String MARK_URL_DOLOGIN = "url_dologin";
    private static final String MARK_URL_DOLOGOUT = "url_dologout";
    private static final long serialVersionUID = 1L;

    private static final String ACTION_DO_LOGOUT = "dologout";

    /**
     * Build the Login page
     * 
     * @param request
     *            The HTTP request
     * @return The XPage object containing the page content
     */
    @View( value = VIEW_HOME, defaultView = true )
    public XPage getHomePage( HttpServletRequest request )
    {
        Map<String, Object> model = getModel( );

        String strError = request.getParameter( Constants.PARAMETER_ERROR );

        if ( strError != null )
        {
            addError( strError );
        }

        LuteceUser user = SecurityService.getInstance( ).getRegisteredUser( request );

        model.put( MARK_USER, user );
        model.put( MARK_URL_DOLOGIN, MyLuteceApp.getDoLoginUrl( ) );
        model.put( MARK_URL_DOLOGOUT, MyLuteceApp.getDoLogoutUrl( ) );

        return getXPage( TEMPLATE_LOGIN_PAGE, request.getLocale( ), model );
    }
    /**
     * Logout action
     * 
     * @param request
     *            The HTTP request
     * @return The XPage object containing the page content
     */
    @Action( ACTION_DO_LOGOUT )
    public XPage doLogout( HttpServletRequest request )
    {
        LuteceUser user = SecurityService.getInstance( ).getRegisteredUser( request );
        String strIdTokenInt=null;
        if(user!=null && user instanceof Oauth2User)
        {
               Oauth2User oauth2User = (Oauth2User) user;
               strIdTokenInt=oauth2User.getToken().getIdTokenString();
               //logout user
               SecurityService.getInstance( ).logoutUser( request );
        }
        //redirect to the logout servlet
        UrlItem url = new UrlItem( Constants.OAUTH2_LOGOUT_SERVLET_PATH );
        if(strIdTokenInt!=null)
        {
           url.addParameter( Constants.PARAMETER_ID_TOKEN_HINT, strIdTokenInt );
        }

        return redirect( request,AppPathService.getAbsoluteUrl(request, url.getUrl()));
    }


}
