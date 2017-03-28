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
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal

import net.shibboleth.idp.attribute.IdPAttribute
import net.shibboleth.idp.attribute.StringAttributeValue



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
    }


    protected void doExecute(@NotNull ProfileRequestContext profileRequestContext,
                             @NotNull AuthenticationContext authenticationContext) {


        accountLinkingUserContext = authenticationContext.getSubcontext(AccountLinkingUserContext.class, true)
        def usernames = accountLinkingUserContext.usernames
        log.debug("{} usernames: {}", logPrefix, usernames)
        def accountLinked = accountLinkingUserContext.accountLinked
        log.debug("{} accountLinked: {}", logPrefix, accountLinked)

        if ( usernames.contains(accountLinked) ) {
            log.info("{} account linking successful for {}", logPrefix, accountLinked)
            buildAuthenticationResult(profileRequestContext, authenticationContext)

            SubjectContext subjectContext =
                    profileRequestContext.getSubcontext(SubjectContext.class, true)
            SubjectCanonicalizationContext subjectCanonicalizationContext =
                    profileRequestContext.getSubcontext(SubjectCanonicalizationContext.class, true)

            log.debug("{} authenticationContext authenticationResults: {}", logPrefix,
                    authenticationContext.getAuthenticationResult())
            subjectContext.setPrincipalName(accountLinkingUserContext.accountLinked)
        } else {
            log.warn("{} candidate {} not among allowed usernames {}", logPrefix, accountLinked, usernames)
            handleError(profileRequestContext, authenticationContext, 'AccountError',
                    AuthnEventIds.ACCOUNT_ERROR)
        }
    }

    @Override
    protected Subject populateSubject(@NotNull Subject subject) {
        log.info("{} producing principal: {}", logPrefix, accountLinkingUserContext.accountLinked)
        log.debug("{} subject was: {}", logPrefix, subject)
        log.debug("{} principals were: {}", logPrefix, subject.principals)

        IdPAttribute attr = new IdPAttribute("accountlinkingTaxpayer")
        attr.setValues([new StringAttributeValue(accountLinkingUserContext.taxpayerNumber)])
        IdPAttributePrincipal taxpayerIdPAttributePrincipal = new IdPAttributePrincipal(attr)

        UsernamePrincipal usernamePrincipal =
                new UsernamePrincipal(accountLinkingUserContext.accountLinked)
        Subject newSubject = new Subject()
        log.debug("{} about to add: {}", logPrefix, usernamePrincipal)
        newSubject.getPrincipals().add(usernamePrincipal)
        newSubject.getPrincipals().add(taxpayerIdPAttributePrincipal)
        log.debug("{} principals are now: {}", logPrefix, newSubject.getPrincipals())
        return newSubject
    }

}
