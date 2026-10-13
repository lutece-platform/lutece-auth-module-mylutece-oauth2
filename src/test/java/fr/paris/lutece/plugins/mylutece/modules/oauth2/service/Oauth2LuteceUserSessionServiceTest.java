/*
 * Copyright (c) 2002-2026, City of Paris
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

import fr.paris.lutece.test.LuteceTestCase;
import fr.paris.lutece.test.mocks.MockHttpServletRequest;

import jakarta.inject.Inject;
import jakarta.servlet.http.HttpSession;

import org.junit.jupiter.api.Test;

/**
 * Notification of the updates of the OAuth2 users to their sessions
 */
public class Oauth2LuteceUserSessionServiceTest extends LuteceTestCase
{
    @Inject
    private Oauth2LuteceUserSessionService _service;

    /**
     * A notification marks every session of the user as out of date, once
     */
    @Test
    public void testNotifyMarksTheSessionsOfTheUser( )
    {
        HttpSession session1 = newSession( );
        HttpSession session2 = newSession( );
        HttpSession sessionOther = newSession( );
        _service.addLuteceUserSession( "user-notify", session1 );
        _service.addLuteceUserSession( "user-notify", session2 );
        _service.addLuteceUserSession( "other-notify", sessionOther );

        _service.notifyLuteceUserUpdating( "user-notify" );

        assertFalse( _service.isLuteceUserUpToDate( session1 ) );
        assertTrue( _service.isLuteceUserUpToDate( session1 ) );
        assertFalse( _service.isLuteceUserUpToDate( session2 ) );
        assertTrue( _service.isLuteceUserUpToDate( sessionOther ) );

        // Every notification counts, not only the first one
        _service.notifyLuteceUserUpdating( "user-notify" );
        assertFalse( _service.isLuteceUserUpToDate( session1 ) );
    }

    /**
     * A session opened after a notification already holds the updated user
     */
    @Test
    public void testSessionOpenedAfterTheNotification( )
    {
        _service.notifyLuteceUserUpdating( "user-later" );
        HttpSession session = newSession( );
        _service.addLuteceUserSession( "user-later", session );

        assertTrue( _service.isLuteceUserUpToDate( session ) );
    }

    /**
     * No session, or a session without OAuth2 user, has nothing to reload
     */
    @Test
    public void testSessionWithoutUser( )
    {
        assertTrue( _service.isLuteceUserUpToDate( null ) );
        assertTrue( _service.isLuteceUserUpToDate( newSession( ) ) );
    }

    private static HttpSession newSession( )
    {
        return new MockHttpServletRequest( ).getSession( true );
    }
}
