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
import org.springframework.webflow.execution.Action
import org.springframework.webflow.execution.Event
import org.springframework.webflow.core.collection.LocalAttributeMap

import it.unimore.shibboleth.idp.accountlinking.authn.impl.AccountLinkingUserContext

import org.springframework.webflow.execution.RequestContext

import net.shibboleth.idp.authn.context.AuthenticationContext
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty


@Slf4j
class ValidateUsernamesArity implements Action {

    @NotEmpty
    private AccountLinkingUserContext accountLinkingUserContext

    def logPrefix = "ValidateUsernamesArity"

    /** Constructor */
    public ValidateUsernamesArity() {
        super()
        log.debug("{} Constructor ValidateUsernamesArity()", logPrefix)
    }

    Event execute(RequestContext context) {

        AuthenticationContext authenticationContext = context.getFlowScope().get("authenticationContext")
        accountLinkingUserContext = authenticationContext.getSubcontext(AccountLinkingUserContext.class, true)
        def usernames = accountLinkingUserContext.usernames
        log.debug("{} usernames: {}", logPrefix, usernames)
        def arity =  usernames.size();
        if (arity == 0) {
            Event event = new Event(this, "no_match")
            log.debug("{} event: {}", logPrefix, event)
            return event
        } else if (arity == 1) {
            accountLinkingUserContext.accountLinked = usernames.first()
            Event event = new Event(this, "one_match")
            log.debug("{} event: {}", logPrefix, event)
            log.debug("{} with accountlinked uid: {}", logPrefix, usernames.first())
            return event
        } else {
            LocalAttributeMap attrMap = new LocalAttributeMap("usernames", usernames)
            Event event = new Event(this, "many_match", attrMap)
            log.debug("{} event: {}", logPrefix, event)
            return event
        }

    }

}
