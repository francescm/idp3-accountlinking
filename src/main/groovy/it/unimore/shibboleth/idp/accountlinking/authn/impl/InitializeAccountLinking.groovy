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

import net.shibboleth.idp.attribute.context.AttributeContext
import net.shibboleth.idp.attribute.StringAttributeValue
import net.shibboleth.idp.attribute.IdPAttribute

import net.shibboleth.idp.authn.context.SubjectCanonicalizationContext
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal

import org.opensaml.profile.context.ProfileRequestContext
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty

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

        SubjectCanonicalizationContext subjectCanonicalizationContext =
                profileRequestContext.getSubcontext("net.shibboleth.idp.authn.context.SubjectCanonicalizationContext")
        log.debug("{} subject c14n context: {}", logPrefix, subjectCanonicalizationContext)

        def uid_attrs = []
        AttributeContext attributeContext = subjectCanonicalizationContext.getSubcontext(AttributeContext.class)
        log.debug("{} alleged attributeContext: {}", logPrefix, attributeContext)

        if (attributeContext) {
            uid_attrs = attributeContext.getIdPAttributes().get("uid")
        }

        def principalName = null
        def subject = subjectCanonicalizationContext.getSubject()

        // just for log
        log.debug("{} subject: {}", logPrefix, subject)
        subject.getPrincipals().each {princ ->
            log.debug("{} princ: {}", logPrefix, princ)
        }

        // copies IdPAttributePrincipals (many) in a map
        def attrsMap = [:]
        def idpAttrs = subject.getPrincipals(net.shibboleth.idp.authn.principal.IdPAttributePrincipal.class)
        idpAttrs.each {attr ->
            log.debug("{} IdP attr: {}", logPrefix, attr)
            attrsMap.put(attr.getName(), attr.getAttribute().getValues() )
        }
        log.debug("{} attrmap: {}", logPrefix, attrsMap)

        // copies AuthnContextClassRefPrincipal (many) in a list
        def authnClassRefPrincList = []
        def authnCtxClassRefPrincs = subject.getPrincipals(net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal.class)
        authnCtxClassRefPrincs.each {princ ->
            log.debug("{} authnCtxRefPrinc: {}", logPrefix, princ)
            authnClassRefPrincList.add(princ.getName())
        }
        log.debug("{} authnClassRefPrincList: {}", logPrefix, authnClassRefPrincList)


        // sets principalName (a string)
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
            log.debug("{} uids found: {}", logPrefix, uid_attrs)
            accountLinkingUserContext = authenticationContext.getSubcontext(AccountLinkingUserContext.class, true)
            log.debug("{} accountlinkingUserContext: {}", logPrefix, accountLinkingUserContext)
            if (! accountLinkingUserContext.initialized) {
                accountLinkingUserContext.initialized = true
            }

            accountLinkingUserContext.taxpayerNumber = taxpayerNumber

            IdPAttribute spid_taxpayer = new IdPAttribute("spid_taxpayer")
            spid_taxpayer.setValues([new StringAttributeValue(taxpayerNumber)])
            accountLinkingUserContext.spid_taxpayer = spid_taxpayer

            if (! accountLinkingUserContext.usernames ) {
                if ( ( ! uid_attrs ) || ( uid_attrs == []) ) {
                    IdPAttribute taxpayernumber = new IdPAttribute("accountlinkingTaxpayer")
                    taxpayernumber.setValues([new StringAttributeValue(accountLinkingUserContext.taxpayerNumber)])
                    IdPAttributePrincipal taxpayerIdPAttributePrincipal = new IdPAttributePrincipal(taxpayernumber)
                    subject.getPrincipals().add(taxpayerIdPAttributePrincipal)
                    accountLinkingUserContext.usernames = []
                } else {
                    accountLinkingUserContext.usernames = uid_attrs.getValues().collect { it.getValue() }
                }
            }
            if (attrsMap["spid_email"]) {
                accountLinkingUserContext.spid_email = attrsMap["spid_email"]
            }
            if (attrsMap["spid_gn"]) {
                accountLinkingUserContext.spid_gn = attrsMap["spid_gn"]
            }
            if (attrsMap["spid_sn"]) {
                accountLinkingUserContext.spid_sn = attrsMap["spid_sn"]
            }
            accountLinkingUserContext.authnContextClassRefPrincipals = authnClassRefPrincList

        } catch (Exception e) {
            log.warn("${logPrefix} Error in doExecute", e)
        }
    }
}
