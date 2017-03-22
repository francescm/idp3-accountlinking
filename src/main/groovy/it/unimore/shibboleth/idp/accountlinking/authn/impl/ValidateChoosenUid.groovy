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

import com.sun.istack.internal.NotNull
import groovy.util.logging.Slf4j

import it.unimore.shibboleth.idp.accountlinking.authn.impl.AccountLinkingUserContext

import net.shibboleth.idp.authn.context.AuthenticationContext
import net.shibboleth.idp.authn.AbstractValidationAction
import net.shibboleth.idp.authn.AuthnEventIds

import org.opensaml.profile.context.ProfileRequestContext

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty
import net.shibboleth.idp.authn.principal.UsernamePrincipal

import net.shibboleth.idp.authn.context.SubjectCanonicalizationContext
import net.shibboleth.idp.authn.context.SubjectContext

import javax.security.auth.Subject

@Slf4j
class ValidateChoosenUid extends AbstractValidationAction {

    @NotNull
    @NotEmpty
    private AccountLinkingUserContext accountLinkingUserContext

    String logPrefix = "ValidateChoosenUid"

    /** Constructor */
    public ValidateChoosenUid() {
        super()
        log.debug("{} Constructor()", logPrefix)
    }


    protected void doExecute(@NotNull ProfileRequestContext profileRequestContext,
                             @NotNull AuthenticationContext authenticationContext) {


        accountLinkingUserContext = authenticationContext.getSubcontext(AccountLinkingUserContext.class, true)
        def usernames = accountLinkingUserContext.usernames
        log.debug("{} usernames: {}", logPrefix, usernames)
        def accountLinked = accountLinkingUserContext.accountLinked
        log.debug("{} accountLinked: {}", logPrefix, accountLinked)

        log.info("{} itacns login successful", logPrefix)
        buildAuthenticationResult(profileRequestContext, authenticationContext)
        SubjectContext subjectContext =
                profileRequestContext.getSubcontext(SubjectContext.class, true)
        SubjectCanonicalizationContext subjectCanonicalizationContext =
                    profileRequestContext.getSubcontext(SubjectCanonicalizationContext.class, true)

        log.debug("{} subjectC14nContext subject: {}", logPrefix, subjectCanonicalizationContext.getSubject())
        log.debug("{} subject subject: {}", logPrefix, subjectContext.getSubjects())
        log.debug("{} subject principal name: {}", logPrefix, subjectContext.getPrincipalName())
        subjectContext.setPrincipalName(accountLinkingUserContext.accountLinked)
        subjectCanonicalizationContext.setPrincipalName(accountLinkingUserContext.accountLinked)


    }

    @Override
    protected Subject populateSubject(@NotNull Subject subject) {
        log.info("{} producing principal: {}", logPrefix, accountLinkingUserContext.accountLinked)
        log.debug("{} subject was: {}", logPrefix, subject)
        log.debug("{} principals were: {}", logPrefix, subject.principals)
        UsernamePrincipal usernamePrincipal =
                new UsernamePrincipal(accountLinkingUserContext.accountLinked)
        log.debug("{} about to add: {}", logPrefix, usernamePrincipal)
        subject.getPrincipals().add(usernamePrincipal)
        log.debug("{} principals are now: {}", logPrefix, subject.getPrincipals())
        return subject
    }

}
