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

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Named;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@ApplicationScoped
@Named( "mylutece-oauth2.oauth2LuteceUserSessionService" )
public class Oauth2LuteceUserSessionService implements IOauth2LuteceUserSessionService
{
    private static Map<String, Oauth2LuteceUserSession> _hashSession = new HashMap<>( );
    private static Map<String, Set<String>> _hashLuteceUserName = new HashMap<>( );

    /**
     * Default constructor for CDI
     */
    public Oauth2LuteceUserSessionService( )
    {
        // Default constructor
    }

    public boolean isLuteceUserUpToDate( String strSession )
    {
        if ( _hashSession.containsKey( strSession ) && !_hashSession.get( strSession ).isUpToDate( ) )
        {
            _hashSession.get( strSession ).setUpToDate( true );

            return false;
        }

        return true;
    }

    public void addLuteceUserSession( String strLuteceUserName, String strSession )
    {
        if ( !_hashLuteceUserName.containsKey( strLuteceUserName ) )
        {
            _hashLuteceUserName.put( strLuteceUserName, new HashSet<String>( ) );
        }

        _hashLuteceUserName.get( strLuteceUserName ).add( strSession );
        _hashSession.put( strSession, new Oauth2LuteceUserSession( strSession, strLuteceUserName, true ) );
    }

    public void removeLuteceUserSession( String strSession )
    {
        if ( _hashSession.containsKey( strSession ) )
        {
            String strLuteceUserName = _hashSession.get( strSession ).getLuteceUserName( );
            _hashSession.remove( strSession );

            if ( _hashLuteceUserName.containsKey( strLuteceUserName ) )
            {
                _hashLuteceUserName.get( strLuteceUserName ).remove( strSession );

                if ( _hashLuteceUserName.get( strLuteceUserName ).isEmpty( ) )
                {
                    _hashLuteceUserName.remove( strLuteceUserName );
                }
            }
        }
    }

    public void notifyLuteceUserUpdating( String strLuteceUserName )
    {
        if ( _hashLuteceUserName.containsKey( strLuteceUserName ) )
        {
            Set<String> setSession = _hashLuteceUserName.get( strLuteceUserName );

            for ( String strSession : setSession )
            {
                if ( _hashSession.containsKey( strSession ) )
                {
                    _hashSession.get( strSession ).setUpToDate( false );
                }
            }
        }
    }
}
