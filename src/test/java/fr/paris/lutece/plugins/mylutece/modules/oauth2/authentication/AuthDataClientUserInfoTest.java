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
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.junit.jupiter.api.Test;

import fr.paris.lutece.plugins.mylutece.modules.oauth2.service.Oauth2Service;
import fr.paris.lutece.plugins.oauth2.business.Token;
import fr.paris.lutece.test.LuteceTestCase;
import fr.paris.lutece.test.mocks.MockHttpServletRequest;
import fr.paris.lutece.test.mocks.MockHttpServletResponse;
import jakarta.enterprise.inject.Vetoed;
import jakarta.inject.Inject;

/**
 * Sign-in callback of the data client authData with an unusable userinfo answer (AX-03, AX-04, AX-06)
 */
public class AuthDataClientUserInfoTest extends LuteceTestCase
{
    @Inject
    private Oauth2Service _oauth2Service;

    @Vetoed
    private static class StubDataClient extends AuthDataClient
    {
        private static final long serialVersionUID = 1L;
        private final String _strUserInfo;

        StubDataClient( Oauth2Service service, String strUserInfo )
        {
            super( service );
            _strUserInfo = strUserInfo;
        }

        @Override
        public String getData( Token token )
        {
            return _strUserInfo;
        }
    }

    @Vetoed
    private static class RedirectResponse extends MockHttpServletResponse
    {
        private String _strRedirectUrl;

        @Override
        public void sendRedirect( String strUrl ) throws IOException
        {
            _strRedirectUrl = strUrl;
        }
    }

    @Vetoed
    private static class ListAppender extends AbstractAppender
    {
        private final List<LogEvent> _listEvents = new ArrayList<>( );

        ListAppender( )
        {
            super( "AuthDataClientUserInfoTest", null, null, true, Property.EMPTY_ARRAY );
        }

        @Override
        public void append( LogEvent event )
        {
            _listEvents.add( event.toImmutable( ) );
        }
    }

    private static Token newToken( )
    {
        Token token = new Token( );
        token.setAccessToken( "access" );
        return token;
    }

    /**
     * AX-03: getData returns null when the userinfo endpoint answers an HTTP error; the callback must not fail with an
     * uncaught exception
     */
    @Test
    public void testUserInfoErrorDoesNotThrow( )
    {
        StubDataClient client = new StubDataClient( _oauth2Service, null );

        assertDoesNotThrow( ( ) -> client.handleToken( newToken( ), new MockHttpServletRequest( ), new RedirectResponse( ) ) );
    }


}
