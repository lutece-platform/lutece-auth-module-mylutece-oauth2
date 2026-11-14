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
package fr.paris.lutece.plugins.mylutece.modules.oauth2.web;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.junit.jupiter.api.Test;

import fr.paris.lutece.portal.service.i18n.I18nService;
import fr.paris.lutece.test.LuteceTestCase;
import freemarker.cache.FileTemplateLoader;
import freemarker.cache.MultiTemplateLoader;
import freemarker.cache.StringTemplateLoader;
import freemarker.cache.TemplateLoader;
import freemarker.core.HTMLOutputFormat;
import freemarker.template.Configuration;
import freemarker.template.TemplateException;

/**
 * Renders the login page of the module with the HTML auto-escaping of the core: headings in order after the level 1
 * heading, and a sign-in control and images with a text alternative taken from the bundles of the module.
 */
public class Oauth2LoginFormRenderTest extends LuteceTestCase
{
    private static final String TEMPLATES_ROOT = "webapp/WEB-INF/templates";
    private static final String TEMPLATE_LOGIN_FORM = "skin/plugins/mylutece/modules/oauth2/login_form.html";
    /** Stand-in of the core macro login_form.html calls. */
    private static final String MACROS = "mylutece_oauth2_test_macros.ftl";
    private static final String MACROS_SOURCE = "<#macro messages errors=[] rest...><#list errors as e><p>${e}</p></#list></#macro>";
    private static final String URL_DOLOGOUT = "jsp/site/Portal.jsp?page=oauth2&action=dologout";

    /**
     * Renders the login page.
     *
     * @param bConnected
     *            true to render the page of a connected user
     * @param locale
     *            the locale of the page
     * @return the rendering, localized
     * @throws IOException
     *             if the template cannot be read
     * @throws TemplateException
     *             if the rendering fails
     */
    private static String render( boolean bConnected, Locale locale ) throws IOException, TemplateException
    {
        StringTemplateLoader macros = new StringTemplateLoader( );
        macros.putTemplate( MACROS, MACROS_SOURCE );
        Configuration cfg = new Configuration( Configuration.VERSION_2_3_0 );
        cfg.setOutputFormat( HTMLOutputFormat.INSTANCE );
        cfg.setAutoEscapingPolicy( Configuration.ENABLE_IF_DEFAULT_AUTO_ESCAPING_POLICY );
        cfg.setTemplateLoader( new MultiTemplateLoader( new TemplateLoader [ ] {
                new FileTemplateLoader( new File( TEMPLATES_ROOT ) ), macros
        } ) );
        cfg.addAutoInclude( MACROS );

        Map<String, Object> model = new HashMap<>( );
        model.put( "errors", new String [ ] {
                "a&b <i>c</i>"
        } );
        if ( bConnected )
        {
            model.put( "user", new Object( ) );
        }
        model.put( "url_dologout", URL_DOLOGOUT );
        StringWriter writer = new StringWriter( );
        cfg.getTemplate( TEMPLATE_LOGIN_FORM ).process( model, writer );

        return I18nService.localize( writer.toString( ), locale );
    }

    /**
     * An anonymous user gets a level 2 heading and a sign-in control named by its text alternative; the error is written
     * as text.
     *
     * @throws Exception
     *             if the rendering fails
     */
    @Test
    public void testAnonymous( ) throws Exception
    {
        String strHtml = render( false, Locale.ENGLISH );

        assertTrue( strHtml.contains( "<h1>Authentication via Oauth2</h1>" ), strHtml );
        assertTrue( strHtml.contains( "<h2>Connect via Oauth2</h2>" ), strHtml );
        assertTrue( strHtml.contains( "alt=\"Sign in via Oauth2\"" ), strHtml );
        assertTrue( strHtml.contains( "<p>a&amp;b &lt;i&gt;c&lt;/i&gt;</p>" ), strHtml );
        assertFalse( strHtml.contains( "<h3>" ), strHtml );
    }

    /**
     * A connected user gets a level 2 heading, a decorative badge and a sign-out link whose icon is hidden from assistive
     * technologies.
     *
     * @throws Exception
     *             if the rendering fails
     */
    @Test
    public void testConnected( ) throws Exception
    {
        String strHtml = render( true, Locale.ENGLISH );

        assertTrue( strHtml.contains( "<h2>You are connected via Oauth2</h2>" ), strHtml );
        assertTrue( strHtml.contains( "oauth2.png\" alt=\"\"" ), strHtml );
        assertTrue( strHtml.contains( "<a href=\"jsp/site/Portal.jsp?page=oauth2&amp;action=dologout\"" ), strHtml );
        assertTrue( strHtml.contains( "<i class=\"glyphicon glyphicon-log-out\" aria-hidden=\"true\"></i>" ), strHtml );
        assertFalse( strHtml.contains( "<h3>" ), strHtml );
    }

    /**
     * The French texts come from the French bundle, every key is resolved.
     *
     * @throws Exception
     *             if the rendering fails
     */
    @Test
    public void testFrenchTexts( ) throws Exception
    {
        String strHtml = render( false, Locale.FRENCH );

        assertTrue( strHtml.contains( "<h2>Connectez vous via Oauth2</h2>" ), strHtml );
        assertTrue( strHtml.contains( "alt=\"Me connecter via Oauth2\"" ), strHtml );
        assertFalse( strHtml.contains( "#i18n" ), strHtml );
    }
}
