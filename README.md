### Kerberos golden ticket generation script

**Required: -domain, -sid, -krbtgt**

Example: 
```bash
./golden -domain CONTOSO.COM -sid S-1-5-21-1234567890-1234567890-1234567890-500 -krbtgt aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

`-dc` Domain Controller FQDN (e.g., dc1.contoso.com)

`-domain` Domain name (e.g., contoso.com)

`-duration` Ticket validity in hours (default 10)

`-groups` Group IDs (comma separated) (default "513,512,520,518,519")

`-id` User ID (RID) (default 500)

`-krbtgt` NTLM hash of krbtgt account

`-out` Output file (default: stdout)

`-sid` User's SID (e.g., S-1-5-21-1234567890-1234567890-1234567890-500)

`-user` Username to impersonate (default "Administrator")
