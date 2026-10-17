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

import fr.paris.lutece.portal.service.cache.Lutece107Cache;
import fr.paris.lutece.portal.service.cache.LuteceCache;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.servlet.http.HttpSession;

import java.util.Objects;
import java.util.UUID;

@ApplicationScoped
@Named( "mylutece-oauth2.oauth2LuteceUserSessionService" )
public class Oauth2LuteceUserSessionService implements IOauth2LuteceUserSessionService
{
    // No dot in the name: the core reads the configuration of a cache from core.cache.status.<name>.<property>, cut at the
    // first dot. Declared eternal in mylutece-oauth2.properties: an expired entry would lose the notification of a user
    // who comes back after the expiry (1000 s by default)
    static final String CACHE_NAME = "mylutece-oauth2UserVersionCache";
    private static final String ATTRIBUTE_USER_NAME = "mylutece-oauth2.userName";
    private static final String ATTRIBUTE_USER_VERSION = "mylutece-oauth2.userVersion";

    // Version of each notified user, changed by every notification. The cache is shared by the instances of the site
    // (Hazelcast in a cluster) and the HTTP session too: a notification received by any instance reaches the sessions of
    // the user whatever the instance serving them. A disabled cache would lose the notifications: the cache is required
    // (never disabled, whatever the status saved in the database). A reset only makes every session reload its user once
    @Inject
    @LuteceCache( cacheName = CACHE_NAME, keyType = String.class, valueType = String.class, enable = true, preventGlobalReset = true, required = true )
    private Lutece107Cache<String, String> _cacheUserVersion;

    /**
     * Default constructor for CDI
     */
    public Oauth2LuteceUserSessionService( )
    {
        // Default constructor
    }

    @Override
    public boolean isLuteceUserUpToDate( HttpSession session )
    {
        String strLuteceUserName = ( session != null ) ? (String) session.getAttribute( ATTRIBUTE_USER_NAME ) : null;

        if ( strLuteceUserName == null )
        {
            return true;
        }

        String strVersion = _cacheUserVersion.get( strLuteceUserName );

        if ( Objects.equals( strVersion, session.getAttribute( ATTRIBUTE_USER_VERSION ) ) )
        {
            return true;
        }

        // A null version (entry evicted) removes the attribute
        session.setAttribute( ATTRIBUTE_USER_VERSION, strVersion );

        return false;
    }

    @Override
    public void addLuteceUserSession( String strLuteceUserName, HttpSession session )
    {
        session.setAttribute( ATTRIBUTE_USER_NAME, strLuteceUserName );
        session.setAttribute( ATTRIBUTE_USER_VERSION, _cacheUserVersion.get( strLuteceUserName ) );
    }

    @Override
    public void notifyLuteceUserUpdating( String strLuteceUserName )
    {
        // A new random value rather than a counter: no read-modify-write between the instances
        _cacheUserVersion.put( strLuteceUserName, UUID.randomUUID( ).toString( ) );
    }
}
