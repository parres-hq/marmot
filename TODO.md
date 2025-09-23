# What needs to be standardized

1. Base protocol NIP-EE
1. Nostr Group Data Extension
1. E2EE media
1. Read receipts and online indicators
1. Multi device/client syncing
1. multi device/client encrypted backup
1. Audio and video calls
1. Notifications??


- Describe all the variations of Proposals and Commits and who can do it?
- Describe other extensions and how to use them?
- Describe checks that must be performed? Look at how MLS talks about required validations

# Required Validations

- Validate new groups use the required extensions
- Validate that no proposal attempts to change the identity on any credentials in the group
- Validate that the Application Message unsigned events have the same pubkey as the leaf node credential that sent the message.

