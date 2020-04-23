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
import net.shibboleth.idp.authn.AbstractExtractionAction
import net.shibboleth.idp.authn.AuthnEventIds
import net.shibboleth.idp.authn.context.AuthenticationContext
import net.shibboleth.idp.profile.ActionSupport
import net.shibboleth.utilities.java.support.primitive.StringSupport
import org.opensaml.profile.context.ProfileRequestContext

import javax.annotation.Nonnull
import javax.servlet.http.HttpServletRequest

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty

@Slf4j
class ProcessUidForm extends AbstractExtractionAction {

    @NotEmpty
    private AccountLinkingUserContext accountLinkingUserContext

    /** Constructor */
    public ProcessUidForm() {
        super()
    }

    String logPrefix = "ProcessUidForm"

    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
                             @Nonnull final AuthenticationContext authenticationContext) {
        final HttpServletRequest request = getHttpServletRequest()

        if (!request) {
            log.debug("{} HttpServletRequest is empty", logPrefix)
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS)
            return
        }

        accountLinkingUserContext = authenticationContext.getSubcontext(AccountLinkingUserContext.class, true)

        def j_account_linked = StringSupport.trimOrNull(request.getParameter("j_account_linked"))
        log.info("{} j_account_linked: {}", logPrefix, j_account_linked)
        accountLinkingUserContext.accountLinked = j_account_linked

    }
}
