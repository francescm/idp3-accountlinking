/*
 * Copyright 2024 Francesco Malvezzi <francesco.malvezzi@unimore.it>
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

import net.shibboleth.idp.authn.context.AuthenticationContext
import net.shibboleth.idp.authn.AbstractValidationAction
import net.shibboleth.idp.authn.AuthnEventIds

import org.opensaml.profile.context.ProfileRequestContext

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty
import net.shibboleth.idp.authn.principal.UsernamePrincipal
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal
import net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal

import net.shibboleth.idp.attribute.IdPAttribute
import net.shibboleth.idp.attribute.StringAttributeValue



import net.shibboleth.idp.authn.context.SubjectCanonicalizationContext
import net.shibboleth.idp.authn.context.SubjectContext

import javax.security.auth.Subject

@Slf4j
class ValidateChoosenUid extends AbstractValidationAction {

    @NotEmpty
    private AccountLinkingUserContext accountLinkingUserContext

    String logPrefix = "ValidateChoosenUid"

    /** Constructor */
    public ValidateChoosenUid() {
        super()
    }


    protected void doExecute(@NotEmpty ProfileRequestContext profileRequestContext,
                             @NotEmpty AuthenticationContext authenticationContext) {


        accountLinkingUserContext = authenticationContext.ensureSubcontext(AccountLinkingUserContext.class)
        def usernames = accountLinkingUserContext.usernames
        log.debug("{} usernames: {}", logPrefix, usernames)
        def accountLinked = accountLinkingUserContext.accountLinked
        log.debug("{} accountLinked: {}", logPrefix, accountLinked)

        if ( usernames.contains(accountLinked) ) {
            log.info("{} account linking successful for {}", logPrefix, accountLinked)
            log.info("{} authenticationContext: {}", logPrefix, authenticationContext)
            log.info("{} profileRequestContext: {}", logPrefix, profileRequestContext)
            buildAuthenticationResult(profileRequestContext, authenticationContext)

            SubjectContext subjectContext =
                    profileRequestContext.getSubcontext(SubjectContext.class, true)
            SubjectCanonicalizationContext subjectC14nContext =
                    profileRequestContext.getSubcontext(SubjectCanonicalizationContext.class, true)

            log.debug("{} subjectContext's subjects: {}", logPrefix,
                    subjectContext.getSubjects())
            log.debug("{} subjectC14nContext's subject: {}", logPrefix,
                    subjectC14nContext.getSubject())
            log.debug("{} authenticationContext authenticationResults: {}", logPrefix,
                    authenticationContext.getAuthenticationResult())
            subjectC14nContext.setPrincipalName(accountLinkingUserContext.accountLinked)
            subjectContext.setPrincipalName(accountLinkingUserContext.accountLinked)
        } else {
            log.warn("{} candidate {} not among allowed usernames {}", logPrefix, accountLinked, usernames)
            // handleError is a method of net.shibboleth.idp.authn.AbstractValidationAction
            handleError(profileRequestContext, authenticationContext, 'AccountError',
                    AuthnEventIds.ACCOUNT_ERROR)
        }
    }

    @Override
    protected Subject populateSubject(@NotEmpty Subject subject) {
        log.info("{} producing principal: {}", logPrefix, accountLinkingUserContext.accountLinked)
        log.debug("{} subject was: {}", logPrefix, subject)
        log.debug("{} principals were: {}", logPrefix, subject.principals)


        UsernamePrincipal usernamePrincipal =
                new UsernamePrincipal(accountLinkingUserContext.accountLinked)
        subject.getPrincipals().clear()
        log.debug("{} subject after clear: {}", logPrefix, subject)

        log.debug("{} about to add: {}", logPrefix, usernamePrincipal)
        subject.getPrincipals().add(usernamePrincipal)


        IdPAttribute taxpayernumber = new IdPAttribute("accountlinkingTaxpayer")
        taxpayernumber.setValues([new StringAttributeValue(accountLinkingUserContext.taxpayerNumber)])
        IdPAttributePrincipal taxpayerIdPAttributePrincipal = new IdPAttributePrincipal(taxpayernumber)
        subject.getPrincipals().add(taxpayerIdPAttributePrincipal)

        if (accountLinkingUserContext.spid_email) {
            IdPAttribute attr = new IdPAttribute("spid_email")
            attr.setValues(accountLinkingUserContext.spid_email)
            IdPAttributePrincipal IdPAttributePrincipal = new IdPAttributePrincipal(attr)
            subject.getPrincipals().add(IdPAttributePrincipal)
        }
        if (accountLinkingUserContext.spid_sn) {
            IdPAttribute attr = new IdPAttribute("spid_sn")
            attr.setValues(accountLinkingUserContext.spid_sn)
            IdPAttributePrincipal IdPAttributePrincipal = new IdPAttributePrincipal(attr)
            subject.getPrincipals().add(IdPAttributePrincipal)
        }
        if (accountLinkingUserContext.spid_gn) {
            IdPAttribute attr = new IdPAttribute("spid_gn")
            attr.setValues(accountLinkingUserContext.spid_gn)
            IdPAttributePrincipal IdPAttributePrincipal = new IdPAttributePrincipal(attr)
            subject.getPrincipals().add(IdPAttributePrincipal)
        }
        if (accountLinkingUserContext.spid_code) {
            IdPAttribute attr = new IdPAttribute("spid_code")
            attr.setValues(accountLinkingUserContext.spid_code)
            IdPAttributePrincipal IdPAttributePrincipal = new IdPAttributePrincipal(attr)
            subject.getPrincipals().add(IdPAttributePrincipal)
        }
        appPrincipal(subject, "spid_dateofbirth", accountLinkingUserContext.spid_dateofbirth)

        accountLinkingUserContext.authnContextClassRefPrincipals.each { princ_name ->
            log.debug("{} adding now princ: {}", logPrefix, princ_name)
            AuthnContextClassRefPrincipal authCtxClassRefPrinc = new AuthnContextClassRefPrincipal(princ_name)
            subject.getPrincipals().add(authCtxClassRefPrinc)
        }


        log.debug("{} subject is now: {}", logPrefix, subject)
        log.debug("{} principals are now: {}", logPrefix, subject.getPrincipals())
        return subject
    }

    private void appPrincipal(@NotEmpty Subject subject, principalName, principalValue) {
        if (principalValue) {
            IdPAttribute attr = new IdPAttribute(principalName)
            attr.setValues(principalValue)
            IdPAttributePrincipal IdPAttributePrincipal = new IdPAttributePrincipal(attr)
            subject.getPrincipals().add(IdPAttributePrincipal)
        }
    }

}
