Modified Defuse.ca's Pastebin
=============================


- Restored original code from defuse.ca (https://github.com/defuse/pastebin)
- Recreated MySQL DB, see database.sql script
- Restructure project, move some files, added bower for client dependencies, easy installation
- Works without url rewriting (redirects to view.php?key={urlkey}), maybe I will change it later

Improvements over the original project
--------------------------------------
- Changed data access library to PDO
- Added 'burn after reading' feature
- Client encryption uses AES-256 not AES-128


Planed features:
----------------
- Delete link to remove pastes before expiration
- Pretty up the UI hasn't really been touched
- What something cool, just let me know?