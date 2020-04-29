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
import org.opensaml.messaging.context.BaseContext

@Slf4j
class AccountLinkingUserContext extends BaseContext {

    def usernames
    def taxpayerNumber
    def accountLinked
    def initialized = false
    def sid_sn
    def spid_gn
    def spid_email
    def code

    /**
     * Get current error and display it to the user.
     *
     * @return an error description
     */

    def getErrorMessage() {
        // TODO: fix proper error codes and add internationalization support
        if (state) {
            state = ""
            return "An error has occurred, please try again!"
        }
        return ""
    }
}
