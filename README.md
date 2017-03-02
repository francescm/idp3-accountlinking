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
an acdemic role (e.g. dean of a faculty).

We need a step to allow user to choose the account to use as 
a principal to forward to attribute resolver.

It happens people with CNS/SPID don't have any local LDAP identity. 
So we must handle the case all the attributes are actually the 
few one in the CNS/SPID assertion (givenName, sn maybe mail).

## Big picture

`accountlinking` flow is where all the logic about 
 querying LDAP about the matching usernames lies. 

`accountlinking` is splitted in three parts:

 1. given a CF, do a LDAP search to fetch uids;
 2. display a "choose-your-uid" form;
 3. do a principal switch with the choosen uid.
 
 
 [1] http://www.agid.gov.it/agenda-digitale/infrastrutture-architetture/spid
