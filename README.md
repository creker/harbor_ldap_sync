# Harbor LDAP sync

Small utility that forces Harbor to sync all LDAP users and groups.

## Usage
```
-harbor_login string
    required  
-harbor_pass string  
    required
-harbor_url string  
    required
-ldap_pass string  
    LDAP search password specified in Harbor config
-sync string  
    comma delimited sync types (users, groups). Required. Example: users,groups
-verbose  
```

## The problem

Harbor (2.5.0 as of writing this) is not able to proactively sync LDAP users and groups. Only when someone logs in will Harbor request user information and group membership from LDAP and insert into its internal database. 

This is not ideal when you're trying to setup access permissions for Harbor projects. When adding new users Harbor is able to give suggestions while you type username but those suggestions come from internal database, not from what's actually in LDAP. Fortunately, if you try to add a user previously unknown to Harbor it will check if it exists in LDAP. If it does, Harbor will automatically onboard it and add to the project. 

The same doesn't work for groups. Not only Harbor is not able to give suggestions but it does not allow adding groups that are not in the internal database already. This means you either have to wait until someone logs in and hopefully is a member of LDAP group you need or you have to manually add LDAP groups to Harbor.

## The solution

This utility solves this by requesting information about all LDAP users and groups that are visible to Harbor and inserting it into Harbor.

User sync is easy. Harbor API is able to return all LDAP users that it has access to directly from LDAP server using existing LDAP auth configuration. We leverage that to add all these users to Harbor. Already existing users are filtered out so Harbor is not forced to keep readding same users over and over again.

Group sync is a bit trickier. Harbor API only allows searching groups by their name. That means we have to request information from LDAP server ourselves. To do that we first obtain LDAP auth configuration from Harbor and use that to contact LDAP server and request all groups. Then, just like with users, already existing groups are filtered out and new ones are added to Harbor.