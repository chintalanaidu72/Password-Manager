# Testing Checklist

| Test Case | Expected Result |
|---|---|
| First launch | Master password creation screen appears |
| Matching master password | Vault is created |
| Non-matching confirmation | Error/warning shown |
| Correct login | Dashboard opens |
| Wrong login | Access denied |
| Add credential | Record appears in vault |
| View credential | Saved information is decrypted correctly |
| Update credential | Updated information is displayed |
| Delete credential | Record is removed |
| Generate password | Random strong password is displayed |
| Restart application | Previously saved records remain available after correct login |

## Manual Test Procedure
1. Start the application.
2. Create a master password of at least 8 characters.
3. Add two or three test credentials.
4. Close and reopen the application.
5. Unlock using the master password.
6. View, update and delete a credential.
7. Test an incorrect master password.
8. Open the SQLite database with a database viewer and observe that credential fields are stored as encrypted text rather than readable passwords.
