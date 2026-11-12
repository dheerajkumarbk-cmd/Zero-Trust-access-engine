package dev.dwarpal.directory;

/**
 * Where the access process tells the credential side that a person appeared or left. Stage 6 plugs the vault in here:
 * a new person gets their switched-off backup credential, a leaver's backup credential is deleted. Until then nothing
 * listens, and {@link #NONE} says so. See {@code docs/iam-stage-links.md}.
 */
public interface CredentialLifecycle {

    /** A person was created by an approved joiner request (their grants exist, they cannot sign in yet). */
    void personCreated(String personId);

    /** A person left: every grant is removed, the account is disabled. */
    void personRemoved(String personId);

    /** The hook that does nothing, until the vault exists. */
    CredentialLifecycle NONE = new CredentialLifecycle() {
        @Override
        public void personCreated(String personId) {
            // Stage 6: create the switched-off backup credential here
        }

        @Override
        public void personRemoved(String personId) {
            // Stage 6: delete the backup credential here
        }
    };
}
