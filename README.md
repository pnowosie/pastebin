Minimalist Open-Source Zero-Knowledge Pastebin
==============================================
Play with online demo at [OpenShift](http://zero-pastebin0.rhcloud.com/) (be patient app is propably idle).

Based on Defuse.ca's Pastebin
-----------------------------

- Restored original code from defuse.ca (https://github.com/defuse/pastebin)
- Recreated MySQL DB, see database.sql script
- Restructure project, move some files, added bower for client dependencies, easy installation
- Works without url rewriting (redirects to index.php?_={urlkey}), index.php handles both add new and view existing pastes
- Features inspired by [ZeroBin](https://github.com/sebsauvage/ZeroBin) but stores data in DB, encrypted again on backend layer.

Improvements over the original project
--------------------------------------
- A little prettier UI with bootstrap
- Changed data access library to PDO
- Added 'burn after reading' feature
- Client encryption uses AES-256 not AES-128
- Delete link to remove pastes before expiration
- Prevent guessing limiting number of request from same IP
- Client encryption key as hashtag, client key generation

Planed features:
----------------
- At the moment I'm happy with features, won't plan anything new
- Want something cool? just let me know
