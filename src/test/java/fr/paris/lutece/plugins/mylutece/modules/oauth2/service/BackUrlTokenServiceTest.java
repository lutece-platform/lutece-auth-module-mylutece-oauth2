/*
 * Copyright (c) 2002-2025, City of Paris
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

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import fr.paris.lutece.portal.service.util.AppPathService;
import fr.paris.lutece.portal.service.util.CryptoService;
import fr.paris.lutece.test.LuteceTestCase;
import fr.paris.lutece.test.mocks.MockHttpServletRequest;

/**
 * Test of {@link BackUrlTokenService} : the back url must survive a legitimate round-trip but any forged, tampered or expired token must be rejected (open
 * redirect prevention).
 *
 * <p>
 * The service under test is a CDI {@code @ApplicationScoped} bean, but here it is instantiated directly to unit-test its logic without booting the whole plugin
 * bean graph (which spans plugin-oauth2 config beans). The {@code @ConfigProperty}-injected validity is set manually on the plain instance.
 * </p>
 */
public class BackUrlTokenServiceTest extends LuteceTestCase
{
    private static final char SEPARATOR = '.';
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder( ).withoutPadding( );

    private final BackUrlTokenService _backUrlTokenService = newBackUrlTokenService( );

    /**
     * Do not let the test container auto-scan the plugin bean graph : this unit test only exercises the plain logic of {@link BackUrlTokenService}.
     */
    @Override
    protected boolean autoFindPluginRelatedBeans( )
    {
        return false;
    }

    /**
     * @return a {@link BackUrlTokenService} instance with a 30-minutes validity, standing in for the CDI-injected {@code @ConfigProperty}
     */
    private static BackUrlTokenService newBackUrlTokenService( )
    {
        BackUrlTokenService service = new BackUrlTokenService( );
        service._lTokenValidityMs = 1800000L;
        return service;
    }

    /**
     * @param request
     *            the current request
     * @return an internal url that passes the isInternalRedirectUrlSafe second check (it starts with the base url)
     */
    private static String getInternalUrl( MockHttpServletRequest request )
    {
        return AppPathService.getBaseUrl( request ) + "jsp/site/Portal.jsp";
    }

    /**
     * A token produced by buildToken must be accepted by verifyToken and yield the original url.
     */
    @Test
    public void testRoundTrip( )
    {
        MockHttpServletRequest request = new MockHttpServletRequest( );
        String strUrl = getInternalUrl( request );

        String strToken = _backUrlTokenService.buildToken( strUrl );

        assertNotNull( strToken );
        assertEquals( strUrl, _backUrlTokenService.verifyToken( strToken, request ) );
    }

    /**
     * A blank url produces an empty token, and an empty/blank token is rejected.
     */
    @Test
    public void testBlankUrlAndToken( )
    {
        MockHttpServletRequest request = new MockHttpServletRequest( );

        assertEquals( "", _backUrlTokenService.buildToken( null ) );
        assertEquals( "", _backUrlTokenService.buildToken( "   " ) );
        assertNull( _backUrlTokenService.verifyToken( null, request ) );
        assertNull( _backUrlTokenService.verifyToken( "", request ) );
    }

    /**
     * Altering the signature of an otherwise valid token must make verification fail.
     */
    @Test
    public void testTamperedSignatureRejected( )
    {
        MockHttpServletRequest request = new MockHttpServletRequest( );
        String strToken = _backUrlTokenService.buildToken( getInternalUrl( request ) );

        // flip the last character of the signature
        char cLast = strToken.charAt( strToken.length( ) - 1 );
        char cReplacement = ( cLast == 'a' ) ? 'b' : 'a';
        String strTampered = strToken.substring( 0, strToken.length( ) - 1 ) + cReplacement;

        assertNull( _backUrlTokenService.verifyToken( strTampered, request ) );
    }

    /**
     * Replacing the payload (the url) while keeping the original signature must make verification fail, because the signature no longer matches.
     */
    @Test
    public void testTamperedPayloadRejected( )
    {
        MockHttpServletRequest request = new MockHttpServletRequest( );
        String strToken = _backUrlTokenService.buildToken( getInternalUrl( request ) );

        int nLastSeparator = strToken.lastIndexOf( SEPARATOR );
        int nFirstSeparator = strToken.indexOf( SEPARATOR );
        String strSignature = strToken.substring( nLastSeparator );
        String strExpiry = strToken.substring( nFirstSeparator, nLastSeparator );

        // swap the url for an external one but keep the genuine expiry and signature
        String strForgedPayload = ENCODER.encodeToString( "https://evil.com".getBytes( StandardCharsets.UTF_8 ) ) + strExpiry;
        String strTampered = strForgedPayload + strSignature;

        assertNull( _backUrlTokenService.verifyToken( strTampered, request ) );
    }

    /**
     * A correctly signed but expired token must be rejected.
     */
    @Test
    public void testExpiredTokenRejected( )
    {
        MockHttpServletRequest request = new MockHttpServletRequest( );
        String strUrl = getInternalUrl( request );

        // forge a token with an expiry one minute in the past, signed with the real app key
        long lPastExpiry = System.currentTimeMillis( ) - 60000L;
        String strPayload = ENCODER.encodeToString( strUrl.getBytes( StandardCharsets.UTF_8 ) ) + SEPARATOR + lPastExpiry;
        String strToken = strPayload + SEPARATOR + CryptoService.hmacSHA256( strPayload );

        assertNull( _backUrlTokenService.verifyToken( strToken, request ) );
    }

    /**
     * A raw, unsigned external url (the typical open-redirect payload an attacker would inject) must be rejected.
     */
    @Test
    public void testForgedExternalUrlRejected( )
    {
        MockHttpServletRequest request = new MockHttpServletRequest( );

        assertNull( _backUrlTokenService.verifyToken( "https://evil.com", request ) );
        assertNull( _backUrlTokenService.verifyToken( "//evil.com", request ) );
        assertNull( _backUrlTokenService.verifyToken( "not.a.token", request ) );
    }
}
