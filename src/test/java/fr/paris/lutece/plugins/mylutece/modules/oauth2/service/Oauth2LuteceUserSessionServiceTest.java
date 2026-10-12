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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;

/**
 * Registry of the sessions of the OAuth2 users, read and written by concurrent requests
 */
public class Oauth2LuteceUserSessionServiceTest
{
    private static final String USER = "user";
    private static final int THREADS = 8;
    private static final int SESSIONS_PER_THREAD = 500;

    /**
     * A notification marks every session of the user as out of date, once
     */
    @Test
    public void testNotifyMarksTheSessionsOfTheUser( )
    {
        Oauth2LuteceUserSessionService service = new Oauth2LuteceUserSessionService( );
        service.addLuteceUserSession( USER, "s1" );
        service.addLuteceUserSession( USER, "s2" );
        service.addLuteceUserSession( "other", "s3" );

        service.notifyLuteceUserUpdating( USER );

        assertFalse( service.isLuteceUserUpToDate( "s1" ) );
        assertTrue( service.isLuteceUserUpToDate( "s1" ) );
        assertFalse( service.isLuteceUserUpToDate( "s2" ) );
        assertTrue( service.isLuteceUserUpToDate( "s3" ) );
    }

    /**
     * Sessions of one user added and removed concurrently: the sessions still registered are all notified (no session
     * lost between the removal of the last session of the user and a new addition)
     */
    @Test
    public void testConcurrentAddAndRemove( ) throws Exception
    {
        Oauth2LuteceUserSessionService service = new Oauth2LuteceUserSessionService( );
        ExecutorService executor = Executors.newFixedThreadPool( THREADS );
        CountDownLatch start = new CountDownLatch( 1 );
        List<Future<?>> futures = new ArrayList<>( );

        try
        {
            for ( int t = 0; t < THREADS; t++ )
            {
                int nThread = t;
                futures.add( executor.submit( ( ) -> {
                    start.await( );
                    for ( int i = 0; i < SESSIONS_PER_THREAD; i++ )
                    {
                        String strSession = nThread + "-" + i;
                        service.addLuteceUserSession( USER, strSession );
                        // Odd sessions are removed, even sessions stay
                        if ( i % 2 == 1 )
                        {
                            service.removeLuteceUserSession( strSession );
                        }
                    }
                    return null;
                } ) );
            }
            start.countDown( );
            for ( Future<?> future : futures )
            {
                future.get( );
            }
        }
        finally
        {
            executor.shutdownNow( );
        }

        service.notifyLuteceUserUpdating( USER );

        for ( int t = 0; t < THREADS; t++ )
        {
            for ( int i = 0; i < SESSIONS_PER_THREAD; i += 2 )
            {
                assertFalse( service.isLuteceUserUpToDate( t + "-" + i ), "session " + t + "-" + i + " not notified" );
            }
        }
    }
}
