# Keycast

## API

- [X] Move authentication checks to the api layer, not the model layer
- [X] Rationalize all the teams methods
- [ ] DRY the error handling in api/http/teams.rs and the rest of the API

## Web

- [X] New policy form
- [X] Permissions form
- [X] policy card (with remove button)
- [ ] Add breadcrumb to new key page
- [ ] add remove key three dots to card
- [ ] Audit log page

## Core

## Signer
- [ ] Run signer as separate process (that is run by concurrently as well)
- [ ] Finish permissions loop for approval

## Config
- [ ] Make sure we reationalize config across all crates