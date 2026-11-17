package cli

import (
	"fmt"
	"os"
	"strings"

	"agpass/internal/api"
	"agpass/internal/client"
	"agpass/internal/server"
	"agpass/internal/sshagent"
)

const sshUsage = `agpass ssh — one shared SSH key for agents, used through agpass

The private key lives in the vault (SYSTEM/ssh) and never leaves it: agents
authenticate through agpass's SSH agent socket, which signs only for hosts the
session is allowed, after checking which server the ssh client is really
connected to.

Human (master password):
  agpass ssh keygen [--comment C] [--force]     create an Ed25519 key
  agpass ssh import FILE [--comment C] [--force]  import an existing private key
  agpass ssh key                                 show the public key to add on GitHub / servers

Agent:
  agpass ssh allow --host github.com --reason "push the fix to acme/crm"
                       automatic for the host of this session's repository;
                       other hosts go to the LLM gatekeeper
  GIT_SSH_COMMAND="$(agpass ssh command)" git push
  $(agpass ssh command) user@server     plain ssh

"agpass ssh command" ignores ~/.ssh/config (so only the agpass key is used) and
accepts only hosts pinned by "ssh allow": give the real host name, user and
port (-p), not aliases from your ssh config.

Requires OpenSSH 8.9 or newer (macOS has it). Forwarding (ssh -A) is refused.
`

func cmdSSHKeygen(args []string) error {
	fs, _ := flags("ssh keygen")
	comment := fs.String("comment", "", "key comment (default agpass@<host>)")
	force := fs.Bool("force", false, "replace the existing key (its public key stops working)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := newConn(true)
	if err != nil {
		return err
	}
	var resp api.SSHKeyResponse
	if err := c.call("POST", "/v1/ssh/keygen", nil, api.SSHKeyRequest{Comment: *comment, Force: *force}, &resp); err != nil {
		return err
	}
	fmt.Println(ui.ok("SSH key created."))
	printSSHKey(resp)
	return nil
}

func cmdSSHImport(args []string) error {
	fs, _ := flags("ssh import")
	comment := fs.String("comment", "", "key comment")
	force := fs.Bool("force", false, "replace the existing key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: agpass ssh import FILE [--force]")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	priv, _, err := sshagent.Normalize(raw, nil, *comment)
	if sshagent.IsPassphraseError(err) {
		pass, perr := readPassword("Key passphrase: ")
		if perr != nil {
			return perr
		}
		priv, _, err = sshagent.Normalize(raw, []byte(pass), *comment)
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", fs.Arg(0), err)
	}
	c, err := newConn(true)
	if err != nil {
		return err
	}
	var resp api.SSHKeyResponse
	req := api.SSHKeyRequest{PrivateKey: string(priv), Comment: *comment, Force: *force}
	if err := c.call("POST", "/v1/ssh/import", nil, req, &resp); err != nil {
		return err
	}
	fmt.Println(ui.ok("SSH key imported.") + " The file " + fs.Arg(0) + " is no longer needed by agpass.")
	printSSHKey(resp)
	return nil
}

func cmdSSHKey(args []string) error {
	fs, admin := flags("ssh key")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := newConn(*admin)
	if err != nil {
		return err
	}
	var resp api.SSHKeyResponse
	if err := c.call("GET", "/v1/ssh/key", nil, nil, &resp); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(resp)
	}
	printSSHKey(resp)
	return nil
}

func printSSHKey(k api.SSHKeyResponse) {
	fmt.Printf("\n%s\n\n", k.PublicKey)
	fmt.Printf("Fingerprint: %s\n", k.Fingerprint)
	fmt.Println(ui.dim("Add the line above as an SSH key on GitHub (ideally a separate account for agents),"))
	fmt.Println(ui.dim("or to ~/.ssh/authorized_keys on servers agents may log in to."))
}

func cmdSSHAllow(args []string) error {
	fs, _ := flags("ssh allow")
	host := fs.String("host", "", "host to authenticate to, e.g. github.com or server:2222 (required)")
	reason := fs.String("reason", "", "what you need SSH for (required)")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" {
		return fmt.Errorf("usage: agpass ssh allow --host HOST --reason REASON")
	}
	c := client.New(server.SocketPath(dataDir()))
	var resp api.SSHAllowResponse
	if err := c.Do("POST", "/v1/ssh/allow", nil, api.SSHAllowRequest{Host: *host, Reason: *reason}, &resp); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(resp)
	}
	if !resp.Granted {
		fmt.Printf("denied   ssh to %s\n", clean(resp.Host))
		if resp.Explanation != "" {
			fmt.Println("\n" + clean(resp.Explanation))
		}
		return fmt.Errorf("no SSH permission for %s", resp.Host)
	}
	fmt.Printf("granted  ssh to %s (%s)\n", clean(resp.Host), clean(resp.By))
	for _, fp := range resp.HostKeys {
		fmt.Printf("  host key %s\n", fp)
	}
	fmt.Printf("\nUse it with:  GIT_SSH_COMMAND=\"$(agpass ssh command)\" git push\n")
	return nil
}

// cmdSSHCommand prints an ssh command line that authenticates only with the
// agpass key and only to pinned hosts. -F /dev/null drops the user's
// ~/.ssh/config, whose IdentityFile entries would otherwise add their own
// keys; IdentityFile=none stops the default key files; the agpass
// known_hosts file with strict checking refuses unpinned servers.
func cmdSSHCommand(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: agpass ssh command")
	}
	dir := dataDir()
	sock, known := server.AgentSocketPath(dir), server.KnownHostsPath(dir)
	if strings.ContainsAny(sock+known, " \"'\\") {
		return fmt.Errorf("agpass data directory contains spaces or quotes: %s", dir)
	}
	fmt.Printf("ssh -F /dev/null -o IdentityAgent=%s -o IdentityFile=none -o ForwardAgent=no"+
		" -o UserKnownHostsFile=%s -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes\n", sock, known)
	return nil
}
