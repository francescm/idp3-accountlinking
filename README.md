> This project is work in progress

# c14n flow for Italian taxpayer code

## Notes

Based on shibboleth-idp-3.3.0

## Motivations

Italian academies have to accept authentications 
from X509 CNS/CIE and SPID [1].

In both case after a successful auth the IdP receives as subject 
principal the Italian taxpayer number (codice fiscale).

The codice fiscale can be shared by more than a LDAP identity. 
For instance the same person can have a teaching position and 
an academic role (e.g. dean of a faculty).

We need a step to allow user to choose the account to use as 
a principal to forward to attribute resolver.

It happens people with CNS/SPID don't have any local LDAP identity. 
So we must handle the case all the attributes are actually the 
few one in the CNS/SPID assertion (givenName, sn maybe mail).

## Big picture

`accountlinking` flow is where all the logic about 
 querying LDAP about the matching usernames lies. 

`accountlinking` is split in three parts:

 1. given a CF, do a LDAP search to fetch uids;
 2. display a "choose-your-uid" form;
 3. do a principal switch with the choosen uid.
 
 
 [1] http://www.agid.gov.it/agenda-digitale/infrastrutture-architetture/spid
 
## How to plug this flow

Edit file: `./conf/c14n/subject-c14n.xml`; add inside the 

    <util:list id="shibboleth.PostLoginSubjectCanonicalizationFlows">
    
(around the head of the file) the following bean (at beginning):
 
    <bean id="c14n/accountlinking" 
      parent="shibboleth.PostLoginSubjectCanonicalizationFlow" />
        <property name="activationCondition"
                  ref="shibboleth.usernameIsACF" />
     </bean>

The activation conditions are:

    <bean id="shibboleth.usernameIsACF" parent="shibboleth.Conditions.SubjectName">
       <constructor-arg>
          <bean class="com.google.common.base.Predicates" 
                factory-method="containsPattern"
                c:pattern="^[A-Z0-9]{16}$" />
       </constructor-arg>
    </bean>

    <bean id="shibboleth.usernameIsNotACF" parent="shibboleth.Conditions.NOT">
        <constructor-arg>
          <ref bean="shibboleth.usernameIsACF" />          
        </constructor-arg>
    </bean>