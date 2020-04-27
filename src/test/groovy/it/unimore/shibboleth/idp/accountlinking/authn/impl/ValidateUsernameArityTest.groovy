/*
 * Copyright 2017 Francesco Malvezzi <francesco.malvezzi@unimore.it>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package it.unimore.shibboleth.idp.accountlinking.authn.impl

import net.shibboleth.idp.authn.context.AuthenticationContext

import org.springframework.webflow.execution.RequestContext

import org.springframework.webflow.core.collection.LocalAttributeMap

import org.springframework.webflow.execution.Event

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertFalse
import static org.junit.Assert.assertTrue
import static org.mockito.Mockito.when


import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Before

import org.mockito.Mockito


class ValidateUsernameArityTest {


    @Before
    void setUp() {
        /*

         */
    }

    @Test
    void testExecuteManyMatches()  {

        List<String> usernames = ['johndoe', 'doejohn']

        AuthenticationContext authenticationContext = new AuthenticationContext()
        AccountLinkingUserContext accountLinkingUserContext = authenticationContext.getSubcontext(AccountLinkingUserContext.class, true)
        accountLinkingUserContext.usernames = usernames

        LocalAttributeMap flowScope = new LocalAttributeMap('authenticationContext', authenticationContext)

        RequestContext requestContext = Mockito.mock(RequestContext.class)
        when(requestContext.getFlowScope()).thenReturn(flowScope)

        ValidateUsernamesArity validateUsernamesArity = new ValidateUsernamesArity()

        Event event = validateUsernamesArity.execute(requestContext)

        assertEquals("many_match", event.id)

    }


    @Test
    void testExecuteOneMatch()  {

        List<String> usernames = ['johndoe']

        AuthenticationContext authenticationContext = new AuthenticationContext()
        AccountLinkingUserContext accountLinkingUserContext = authenticationContext.getSubcontext(AccountLinkingUserContext.class, true)
        accountLinkingUserContext.usernames = usernames

        LocalAttributeMap flowScope = new LocalAttributeMap('authenticationContext', authenticationContext)

        RequestContext requestContext = Mockito.mock(RequestContext.class)
        when(requestContext.getFlowScope()).thenReturn(flowScope)

        ValidateUsernamesArity validateUsernamesArity = new ValidateUsernamesArity()

        Event event = validateUsernamesArity.execute(requestContext)

        assertEquals("one_match", event.id)

    }

}
