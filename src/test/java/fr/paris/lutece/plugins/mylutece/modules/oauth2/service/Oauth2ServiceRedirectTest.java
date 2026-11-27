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

import org.junit.jupiter.api.Test;

import fr.paris.lutece.portal.service.util.AppPathService;
import fr.paris.lutece.test.LuteceTestCase;
import fr.paris.lutece.test.mocks.MockHttpServletRequest;
import fr.paris.lutece.test.mocks.MockHttpServletResponse;
import jakarta.enterprise.inject.Vetoed;
import jakarta.inject.Inject;

/**
 * Redirection after a successful sign-in: the callback is served under servlet/plugins/oauth2/, so a relative default
 * URL (mylutece.url.default.redirect=../../Portal.jsp) lands on servlet/Portal.jsp (404)
 */
public class Oauth2ServiceRedirectTest extends LuteceTestCase
{
    private static final String ATTRIBUTE_LOGIN_NEXT_URL = "luteceLoginNextUrl";

    @Inject
    private Oauth2Service _oauth2Service;

    @Vetoed
    private static class RedirectResponse extends MockHttpServletResponse
    {
        private String _strRedirectUrl;

        @Override
        public String encodeRedirectURL( String strUrl )
        {
            // no URL rewriting in the test
            return strUrl;
        }

        @Override
        public void sendRedirect( String strUrl ) throws IOException
        {
            _strRedirectUrl = strUrl;
        }
    }

    private String redirect( MockHttpServletRequest request ) throws IOException
    {
        RedirectResponse response = new RedirectResponse( );
        _oauth2Service.redirect( request, response );
        return response._strRedirectUrl;
    }

    @Test
    public void testNoNextUrlGoesToThePortal( ) throws IOException
    {
        MockHttpServletRequest request = new MockHttpServletRequest( );

        assertEquals( AppPathService.getBaseUrl( request ) + AppPathService.getPortalUrl( ), redirect( request ) );
    }

    @Test
    public void testStoredNextUrlIsKept( ) throws IOException
    {
        MockHttpServletRequest request = new MockHttpServletRequest( );
        String strNextUrl = AppPathService.getBaseUrl( request ) + "jsp/site/Portal.jsp?page=mydashboard";
        request.getSession( true ).setAttribute( ATTRIBUTE_LOGIN_NEXT_URL, strNextUrl );

        assertEquals( strNextUrl, redirect( request ) );
    }

    @Test
    public void testExternalNextUrlIsRefused( ) throws IOException
    {
        MockHttpServletRequest request = new MockHttpServletRequest( );
        request.getSession( true ).setAttribute( ATTRIBUTE_LOGIN_NEXT_URL, "https://evil.example/phishing" );

        assertEquals( AppPathService.getBaseUrl( request ) + AppPathService.getPortalUrl( ), redirect( request ) );
    }
}
