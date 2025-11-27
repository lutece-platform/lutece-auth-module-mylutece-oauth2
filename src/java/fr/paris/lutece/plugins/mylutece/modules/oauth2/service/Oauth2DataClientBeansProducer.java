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

import fr.paris.lutece.plugins.mylutece.modules.oauth2.authentication.AuthDataClient;
import fr.paris.lutece.plugins.mylutece.modules.oauth2.authentication.AuthDataClientJson;
import fr.paris.lutece.plugins.oauth2.dataclient.LogUserInfoDataClient;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * CDI Producer for OAuth2 DataClient-related beans
 */
@ApplicationScoped
public class Oauth2DataClientBeansProducer
{

    @Inject
    private Oauth2Service _Oauth2Service;
    
    /**
     * Default constructor for CDI
     */
    public Oauth2DataClientBeansProducer( )
    {
        // Default constructor
    }
    
    /**
     * Produces the AuthDataClient bean
     * 
     * @param dataServerUri The data server URI
     * @param tokenMethod The token method (e.g., HEADER)
     * @param scopes The scopes as comma-separated string
     * @param isDefault Whether this is the default data client
     * @return The AuthDataClient instance
     */
    @Produces
    @ApplicationScoped
    @Named( "mylutece-oauth2.authDataClient" )
    public AuthDataClient produceAuthDataClient(
        @ConfigProperty( name = "mylutece-oauth2.dataclient.authData.dataServerUri" ) Optional<String> dataServerUri,
        @ConfigProperty( name = "mylutece-oauth2.dataclient.authData.tokenMethod" ) Optional<String> tokenMethod,
        @ConfigProperty( name = "mylutece-oauth2.dataclient.authData.scopes" ) Optional<String> scopes,
        @ConfigProperty( name = "mylutece-oauth2.dataclient.authData.default" ) Optional<Boolean> isDefault )
    {
        AuthDataClient client = new AuthDataClient( _Oauth2Service);
        client.setName( "authData" );
        
        if ( dataServerUri.isPresent( ) )
        {
            client.setDataServerUri( dataServerUri.get( ) );
        }
        
        if ( tokenMethod.isPresent( ) )
        {
            client.setTokenMethod( tokenMethod.get( ) );
        }
        
        // Convert comma-separated scopes to Set
        if ( scopes.isPresent( ) && !scopes.get( ).isEmpty( ) )
        {
            Set<String> scopeSet = new HashSet<>( Arrays.asList( scopes.get( ).split( "," ) ) );
            client.setScope( scopeSet );
        }

        client.setDefault( isDefault.orElse( false ) );
        
        // Note: The 'default' property would need to be handled by the OAuth2 service
        // if it needs to identify the default data client
        
        return client;
    }
    
    /**
     * Produces the AuthDataClientJson bean
     * 
     * @param dataServerUri The data server URI
     * @param tokenMethod The token method (e.g., HEADER)
     * @param scopes The scopes as comma-separated string
     * @param isDefault Whether this is the default data client
     * @return The AuthDataClientJson instance
     */
    @Produces
    @ApplicationScoped
    @Named( "mylutece-oauth2.authDataClientJson" )
    public AuthDataClientJson produceAuthDataClientJson(
        @ConfigProperty( name = "mylutece-oauth2.dataclient.authDataJson.dataServerUri" ) Optional<String> dataServerUri,
        @ConfigProperty( name = "mylutece-oauth2.dataclient.authDataJson.tokenMethod" ) Optional<String> tokenMethod,
        @ConfigProperty( name = "mylutece-oauth2.dataclient.authDataJson.scopes" ) Optional<String> scopes,
        @ConfigProperty( name = "mylutece-oauth2.dataclient.authDataJson.default" ) Optional<Boolean> isDefault )
    {
        AuthDataClientJson client = new AuthDataClientJson(_Oauth2Service );
        client.setName( "authDataJson" );
        
        if ( dataServerUri.isPresent( ) )
        {
            client.setDataServerUri( dataServerUri.get( ) );
        }
        
        if ( tokenMethod.isPresent( ) )
        {
            client.setTokenMethod( tokenMethod.get( ) );
        }
        
        // Convert comma-separated scopes to Set
        if ( scopes.isPresent( ) && !scopes.get( ).isEmpty( ) )
        {
            Set<String> scopeSet = new HashSet<>( Arrays.asList( scopes.get( ).split( "," ) ) );
            client.setScope( scopeSet );
        }
        
        // Note: The 'default' property would need to be handled by the OAuth2 service
        // if it needs to identify the default data client

        client.setDefault( isDefault.orElse( false ) );
        
        return client;
    }
}
