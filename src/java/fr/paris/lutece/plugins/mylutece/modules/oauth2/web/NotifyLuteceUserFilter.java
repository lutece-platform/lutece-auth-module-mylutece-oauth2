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

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import jakarta.enterprise.inject.spi.CDI;

import org.apache.commons.lang3.StringUtils;

import fr.paris.lutece.plugins.mylutece.modules.oauth2.service.IOauth2LuteceUserSessionService;

/**
 * ParisConnectLuteceFilters
 *
 */
@WebFilter(filterName = "Oauth 2 Notify Lutece User", urlPatterns = "/plugins/myluteceoauth2/notifyLuteceUser")
public class NotifyLuteceUserFilter implements Filter
{
    private final static String PARAMETER_UID = "uid";

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void destroy( )
    {
        // nothing
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void doFilter( ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain ) throws IOException, ServletException
    {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String strGuidParameter = request.getParameter( PARAMETER_UID );

        if ( !StringUtils.isEmpty( strGuidParameter ) )
        {
            IOauth2LuteceUserSessionService service = CDI.current( ).select( IOauth2LuteceUserSessionService.class ).get( );
            service.notifyLuteceUserUpdating( strGuidParameter );
        }

        response.setStatus( HttpServletResponse.SC_OK );
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void init( FilterConfig config ) throws ServletException
    {
        // nothing
    }
}
