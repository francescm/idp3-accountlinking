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

import net.shibboleth.idp.attribute.IdPAttribute
import net.shibboleth.idp.attribute.StringAttributeValue
import net.shibboleth.idp.authn.context.AuthenticationContext
import net.shibboleth.idp.authn.context.SubjectCanonicalizationContext


import net.shibboleth.idp.authn.context.AuthenticationErrorContext
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal
import net.shibboleth.idp.authn.principal.UsernamePrincipal
import org.opensaml.profile.context.ProfileRequestContext
import net.shibboleth.idp.authn.context.SubjectContext

import net.shibboleth.idp.authn.AuthenticationFlowDescriptor


import org.springframework.webflow.core.collection.LocalAttributeMap

import org.springframework.webflow.execution.Event

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertFalse
import static org.junit.Assert.assertNull
import static org.junit.Assert.assertTrue
import static org.mockito.Mockito.when


import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Before

import org.mockito.Mockito

import org.powermock.api.mockito.PowerMockito
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import javax.security.auth.Subject

@RunWith(PowerMockRunner.class)
@PrepareForTest(AuthenticationContext.class)
class ValidateChoosenUidTest {

    def authenticationFlowDescriptor
    List<String> usernames = ['tizio', 'caio']
    AccountLinkingUserContext accountLinkingUserContext

    @Before
    void setUp() {
        authenticationFlowDescriptor = new AuthenticationFlowDescriptor()
        authenticationFlowDescriptor.setId("testFlow")
        accountLinkingUserContext = new AccountLinkingUserContext()
        accountLinkingUserContext.usernames = usernames
        accountLinkingUserContext.taxpayerNumber = "JUSTATESTCF"
    }

    @Test
    void testExecuteWhenUidMatches()  {

        def choosenUsername = "tizio"

        accountLinkingUserContext.accountLinked = choosenUsername

        AuthenticationContext authenticationContext = PowerMockito.mock(AuthenticationContext.class)
        ProfileRequestContext profileRequestContext = new ProfileRequestContext()

        when(authenticationContext.getSubcontext(AccountLinkingUserContext.class,
                true))
                .thenReturn(accountLinkingUserContext)

        when(authenticationContext.getAttemptedFlow())
                .thenReturn(authenticationFlowDescriptor)

        ValidateChoosenUid validateChoosenUid = new ValidateChoosenUid()
        validateChoosenUid.doExecute(profileRequestContext, authenticationContext)

        SubjectCanonicalizationContext subjectCanonicalizationContext =
                profileRequestContext.getSubcontext(SubjectCanonicalizationContext.class)

        Subject result = new Subject()
        result.getPrincipals().add(new UsernamePrincipal(choosenUsername))

        IdPAttribute attr = new IdPAttribute("accountlinkingTaxpayer")
        attr.setValues([new StringAttributeValue(accountLinkingUserContext.taxpayerNumber)])
        IdPAttributePrincipal taxpayerIdPAttributePrincipal = new IdPAttributePrincipal(attr)

        result.getPrincipals().add(taxpayerIdPAttributePrincipal)

        assertEquals(result, subjectCanonicalizationContext.subject)

    }

    @Test
    void testExecuteWhenMisMatch()  {

        def choosenUsername = "sempronio"

        accountLinkingUserContext.accountLinked = choosenUsername

        AuthenticationContext authenticationContext = PowerMockito.mock(AuthenticationContext.class)
        ProfileRequestContext profileRequestContext = new ProfileRequestContext()

        when(authenticationContext.getSubcontext(AccountLinkingUserContext.class,
                true))
                .thenReturn(accountLinkingUserContext)

        when(authenticationContext.getAttemptedFlow())
                .thenReturn(authenticationFlowDescriptor)

        ValidateChoosenUid validateChoosenUid = new ValidateChoosenUid()
        validateChoosenUid.doExecute(profileRequestContext, authenticationContext)

        SubjectCanonicalizationContext subjectCanonicalizationContext =
                profileRequestContext.getSubcontext(SubjectCanonicalizationContext.class)
        assertNull(subjectCanonicalizationContext)


    }

}
