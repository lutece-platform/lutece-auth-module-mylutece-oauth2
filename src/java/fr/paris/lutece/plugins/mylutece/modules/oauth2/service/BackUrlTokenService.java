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
import java.security.MessageDigest;
import java.util.Base64;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.CryptoService;
import fr.paris.lutece.util.http.SecurityUtil;

/**
 * Builds and verifies the "back url" carried through the OIDC prompt=none round-trip (parameter
 * {@code bck_prompt_url}).
 *
 * <p>
 * The back url is a request parameter that ends up in a {@code sendRedirect}, so it is a classic open-redirect sink. Instead of relying solely on
 * {@link SecurityUtil#isInternalRedirectUrlSafe} (a deny-list whose robustness depends on the deployed core version and configuration), the url is wrapped in a
 * server-signed token : {@code base64url(url).expiry.hmacSHA256(base64url(url).expiry)}.
 * </p>
 *
 * <p>
 * The HMAC is computed with the application crypto key ({@link CryptoService#hmacSHA256(String)}, key stored in the Datastore, therefore stable across restarts
 * and shared across cluster nodes). Any value forged or tampered with by a client fails the signature check and is rejected, which closes the open redirect
 * regardless of the core version. A short time-to-live bounds replay. The decoded url is still passed through {@link SecurityUtil#isInternalRedirectUrlSafe} as
 * a second line of defense.
 * </p>
 */
@ApplicationScoped
public class BackUrlTokenService
{
    /** Property holding the token validity in milliseconds (defaults to 30 minutes) */
    private static final String PROPERTY_TOKEN_VALIDITY_MS = "mylutece-oauth2.backUrlTokenValidityMs";
    private static final String DEFAULT_TOKEN_VALIDITY_MS = "1800000";
    private static final char SEPARATOR = '.';
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder( ).withoutPadding( );
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder( );

    /** Token validity in milliseconds, injected from the plugin configuration (package-private so unit tests can set it on a plain instance) */
    @Inject
    @ConfigProperty( name = PROPERTY_TOKEN_VALIDITY_MS, defaultValue = DEFAULT_TOKEN_VALIDITY_MS )
    long _lTokenValidityMs;

    /**
     * Default constructor for CDI
     */
    public BackUrlTokenService( )
    {
        // Default constructor
    }

    /**
     * Build a server-signed token wrapping the given internal url, to be transported as the {@code bck_prompt_url} parameter.
     *
     * @param strUrl
     *            the internal url to protect (server-side value)
     * @return the signed token, or an empty string if the url is blank
     */
    public String buildToken( String strUrl )
    {
        if ( StringUtils.isBlank( strUrl ) )
        {
            return StringUtils.EMPTY;
        }

        String strPayload = ENCODER.encodeToString( strUrl.getBytes( StandardCharsets.UTF_8 ) ) + SEPARATOR
                + ( System.currentTimeMillis( ) + _lTokenValidityMs );

        return strPayload + SEPARATOR + CryptoService.hmacSHA256( strPayload );
    }

    /**
     * Verify a token produced by {@link #buildToken(String)} and return the internal url it carries.
     *
     * @param strToken
     *            the token read from the {@code bck_prompt_url} request parameter
     * @param request
     *            the current request (used for the {@link SecurityUtil#isInternalRedirectUrlSafe} second check)
     * @return the verified internal url, or {@code null} if the token is missing, malformed, has an invalid signature, is expired or resolves to an unsafe url
     */
    public String verifyToken( String strToken, HttpServletRequest request )
    {
        if ( StringUtils.isBlank( strToken ) )
        {
            return null;
        }

        int nLastSeparator = strToken.lastIndexOf( SEPARATOR );
        int nFirstSeparator = strToken.indexOf( SEPARATOR );

        if ( nLastSeparator <= nFirstSeparator || nFirstSeparator < 0 )
        {
            return null;
        }

        String strPayload = strToken.substring( 0, nLastSeparator );
        String strProvidedSignature = strToken.substring( nLastSeparator + 1 );

        // constant-time comparison of the HMAC to avoid timing attacks
        byte [ ] expectedSignature = CryptoService.hmacSHA256( strPayload ).getBytes( StandardCharsets.UTF_8 );
        byte [ ] providedSignature = strProvidedSignature.getBytes( StandardCharsets.UTF_8 );

        if ( !MessageDigest.isEqual( expectedSignature, providedSignature ) )
        {
            return null;
        }

        try
        {
            String strEncodedUrl = strPayload.substring( 0, nFirstSeparator );
            long lExpiry = Long.parseLong( strPayload.substring( nFirstSeparator + 1 ) );

            if ( System.currentTimeMillis( ) > lExpiry )
            {
                return null;
            }

            String strUrl = new String( DECODER.decode( strEncodedUrl ), StandardCharsets.UTF_8 );

            // second line of defense : even a (correctly signed) url is still checked against the open-redirect deny-list
            if ( !SecurityUtil.isInternalRedirectUrlSafe( strUrl, request ) )
            {
                return null;
            }

            return strUrl;
        }
        catch( IllegalArgumentException e )
        {
            // malformed expiry or base64 payload
            AppLogService.error( "Oauth2 - malformed back url token", e );
            return null;
        }
    }
}
