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

import org.opensaml.profile.context.ProfileRequestContext
import net.shibboleth.idp.authn.context.AuthenticationContext
import net.shibboleth.idp.authn.AuthenticationResult
import net.shibboleth.idp.authn.principal.UsernamePrincipal
import javax.security.auth.Subject
import java.security.Principal
import net.shibboleth.idp.authn.context.SubjectCanonicalizationContext
import net.shibboleth.idp.attribute.context.AttributeContext

import net.shibboleth.idp.attribute.IdPAttribute


import net.shibboleth.idp.attribute.StringAttributeValue

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertFalse
import static org.junit.Assert.assertTrue
import static org.mockito.Mockito.when

import java.security.Principal

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Before

import org.mockito.Mockito

import org.powermock.api.mockito.PowerMockito
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.core.classloader.annotations.PowerMockIgnore
import org.powermock.modules.junit4.PowerMockRunner

@PowerMockIgnore(["javax.management.*", "com.sun.org.apache.xerces.*", "javax.xml.*", "org.xml.*", "org.w3c.dom.*", "com.sun.org.apache.xalan.*", "javax.activation.*"])
@RunWith(PowerMockRunner.class)
@PrepareForTest([ProfileRequestContext.class, AuthenticationContext.class])
class InitializeAccountLinkingTest {


    @Before
    void setUp() {
        /*

         */
    }

    @Test
    void testDoExecute()  {


        InitializeAccountLinking initAccountLinking = new InitializeAccountLinking()

        ProfileRequestContext profileRequestContext = PowerMockito.mock(ProfileRequestContext.class)

        AuthenticationContext authenticationContext = PowerMockito.mock(AuthenticationContext.class)

        //Profile Action InitializeAccountLinking:
        // Entering doExecute with AuthenticationContext{initiationInstant=2017-03-09T15:40:28.690+01:00,
        // isPassive=false, forceAuthn=false, hintedName=malvezzi, potentialFlows=[authn/Password, authn/X509External],
        // activeResults=[], attemptedFlow=AuthenticationFlowDescriptor{flowId=authn/X509External,
        // supportsPassive=false, supportsForcedAuthentication=false, lifetime=3600000, inactivityTimeout=1800000},
        // signaledFlowId=null, authenticationStateMap={}, resultCacheable=true,
        // initialAuthenticationResult=null,
        // authenticationResult=AuthenticationResult{authenticationFlowId=authn/X509External,
        // authenticatedPrincipal=MLVFNC69H12B819Z, authenticationInstant=2017-03-09T15:41:25.383+01:00,
        // lastActivityInstant=2017-03-09T15:41:25.383+01:00, previousResult=false},
        // completionInstant=1970-01-01T01:00:00.000+01:00}

        List<StringAttributeValue> uid_values = [
                new StringAttributeValue("malvezzi"),
                new StringAttributeValue("146394")
        ]

        def usernames_to_validate = []
        uid_values.each { usernames_to_validate << it.getValue() }

        IdPAttribute uid_attr = new IdPAttribute("uid")
        uid_attr.setValues(uid_values)

        def attrs = new HashSet<IdPAttribute>()
        attrs.add(uid_attr)

        AttributeContext attributeContext = new AttributeContext()
        attributeContext.setIdPAttributes(attrs)

        String cf = "CFVOIDTEST"
        Principal principal = new UsernamePrincipal(cf)

        Subject subject = new Subject()
        subject.getPrincipals().add(principal)

        SubjectCanonicalizationContext subjectCanonicalizationContext = new SubjectCanonicalizationContext()
        subjectCanonicalizationContext.setSubject(subject)
        subjectCanonicalizationContext.addSubcontext(attributeContext, true)

        //AuthenticationResult authenticationResult = new AuthenticationResult("authn/X509External", subject)

        AccountLinkingUserContext accountLinkingUserContext = new AccountLinkingUserContext()

        when(authenticationContext.getSubcontext(AccountLinkingUserContext.class,
                true))
                .thenReturn(accountLinkingUserContext)

        //when(authenticationContext.getAuthenticationResult()).thenReturn(authenticationResult)

        when(profileRequestContext.
                getSubcontext("net.shibboleth.idp.authn.context.SubjectCanonicalizationContext")).
                thenReturn(subjectCanonicalizationContext)

        def aList = new ArrayList()
        aList.add("a element")

        when(profileRequestContext.iterator()).
                thenReturn(aList.iterator())

        initAccountLinking.doExecute(profileRequestContext, authenticationContext)

        assertEquals(accountLinkingUserContext.usernames, usernames_to_validate )
        assertEquals(accountLinkingUserContext.taxpayerNumber, cf)
    }


}
