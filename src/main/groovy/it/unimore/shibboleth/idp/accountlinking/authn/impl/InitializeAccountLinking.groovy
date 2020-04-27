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

import groovy.util.logging.Slf4j
import it.unimore.shibboleth.idp.accountlinking.authn.impl.AccountLinkingUserContext
import net.shibboleth.idp.authn.AbstractExtractionAction
import net.shibboleth.idp.authn.context.AuthenticationContext
import net.shibboleth.idp.authn.principal.UsernamePrincipal

import net.shibboleth.idp.attribute.context.AttributeContext

import net.shibboleth.idp.authn.context.ExternalAuthenticationContext
import net.shibboleth.idp.authn.context.SubjectCanonicalizationContext

import net.shibboleth.idp.authn.AuthenticationResult
import org.opensaml.profile.context.ProfileRequestContext
import net.shibboleth.idp.authn.context.UsernamePasswordContext
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty
import org.springframework.beans.factory.annotation.Value
import javax.security.auth.Subject
import java.security.Principal

import javax.annotation.Nonnull

@Slf4j
public class InitializeAccountLinking extends AbstractExtractionAction {

    @NotEmpty
    private AccountLinkingUserContext accountLinkingUserContext


    InitializeAccountLinking() {
        super()
        log.debug("initializing Account Linking")
    }

    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
                             @Nonnull final AuthenticationContext authenticationContext) {
        log.debug("{} Entering doExecute with {}", logPrefix, authenticationContext)

        log.debug("{} profileContext: {}", logPrefix, profileRequestContext)
        authenticationContext.activeResults.each { result ->
            log.debug("{} active result key: {} value: {}", logPrefix, result.key, result.value)
        }

        def subContext = profileRequestContext.iterator().next()
        log.debug("{} profileRequestContext subContext: {}", logPrefix, subContext)

        /*
        def attrs = attributeContext.getUnfilteredIdPAttributes()
        log.debug("{} attributeContext attrs: {}", logPrefix, attrs)
        def attr_uids = attrs["uid"]
        log.debug("{} attributeContext uids: {}", attr_uids, attrs)
        */

        SubjectCanonicalizationContext subjectCanonicalizationContext =
                profileRequestContext.getSubcontext("net.shibboleth.idp.authn.context.SubjectCanonicalizationContext")
        log.debug("{} subject c14n context: {}", logPrefix, subjectCanonicalizationContext)

        AttributeContext attributeContext = subjectCanonicalizationContext.getSubcontext(AttributeContext.class)
        log.debug("{} alleged attributeContext: {}", logPrefix, attributeContext)

        def uid_attrs = attributeContext.getIdPAttributes().get("uid")
        log.debug("{} alleged uids: {}", logPrefix, uid_attrs)

        def uids = []
        attributeContext.getIdPAttributes().get("uid").getValues().each { uids << it.getValue() }

        def principalName = null
        def subject = subjectCanonicalizationContext.getSubject()
        def princs = subject.getPrincipals(net.shibboleth.idp.authn.principal.UsernamePrincipal.class)
        if (princs.size() == 1) {
            principalName = princs.iterator().next().getName()
        }
        principalName
        log.debug("{} taxpayer number is: {}", logPrefix, principalName )

        String taxpayerNumber = principalName
/*
        AuthenticationResult authenticationResult = authenticationContext.getAuthenticationResult()
        log.debug("{} authentication result: {}", logPrefix, authenticationResult)
        log.debug("{} authentication result subject: {}", logPrefix, authenticationResult.getSubject())
        def principals = authenticationResult.getSubject().getPrincipals(UsernamePrincipal.class)
        log.debug("{} I assume taxpayer number is: {}", logPrefix, principals.toArray().first().getName())
        taxpayerNumber = principals.toArray().first().getName()
*/
        try {
            log.debug("{} uids found: {}", logPrefix, uids)
            accountLinkingUserContext = authenticationContext.getSubcontext(AccountLinkingUserContext.class, true)
            if (!accountLinkingUserContext.initialized) {
                accountLinkingUserContext.usernames = uids
                accountLinkingUserContext.taxpayerNumber = taxpayerNumber
                accountLinkingUserContext.initialized = true
            }

        } catch (Exception e) {
            log.warn("${logPrefix} Error in doExecute", e)
        }
    }
}
