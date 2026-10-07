# Setup

Open https://control.vespoli.me/owner/apps/caretaker and use the common owner login. Register or verify the GitHub App and installation from that pane. OAuth registration callbacks return to the same owner pane and use owner-bound, expiring state.

The existing AppVault, audit R2 bucket and audit D1 database are retained. No setup link secret, separate Access application, OAuth KV or second identity stack is required. Private service bindings connect the capability to `personal-control`.

See the canonical architecture and deployment instructions in https://github.com/susanbeasles/personal-control/blob/main/docs/architecture.md.
