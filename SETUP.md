# Setup

Open https://control.vespoli.me/owner/apps/caretaker and use the common owner login. Register or verify the GitHub App and installation from that pane. OAuth registration callbacks return to the same owner pane and use owner-bound, expiring state.

The existing AppVault, audit R2 bucket and audit D1 database are retained. No setup link secret, separate Access application, OAuth KV or second identity stack is required. Private service bindings connect the capability to `personal-control`.

The pane displays installation phase separately from webhook configuration and received delivery evidence. For an existing App, retain its current vault and webhook secret, configure the central `/webhooks/github/caretaker` URL and the generated manifest's event subscriptions, then verify a signed delivery in the pane. A suspended/deleted installation remains disabled until the owner uses **Verify installation** and GitHub returns the pinned, active installation. The capability never creates a replacement App or changes webhook settings in response to an event.

Local validation does not activate the integration. Release the reviewed gateway and component through `workflow_depot` authorization and the standalone `delivery_control` executor; the legacy direct-deploy script deliberately refuses to run. No provider credentials are required for the offline tests.

See the canonical architecture and deployment instructions in https://github.com/susanbeasles/personal-control/blob/main/docs/architecture.md.
