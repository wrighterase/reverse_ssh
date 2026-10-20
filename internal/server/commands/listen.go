package commands

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/NHAS/reverse_ssh/internal"
	"github.com/NHAS/reverse_ssh/internal/server/multiplexer"
	"github.com/NHAS/reverse_ssh/internal/server/observers"
	"github.com/NHAS/reverse_ssh/internal/server/users"
	"github.com/NHAS/reverse_ssh/internal/terminal"
	"github.com/NHAS/reverse_ssh/internal/terminal/autocomplete"
	"github.com/NHAS/reverse_ssh/pkg/logger"
	"github.com/NHAS/reverse_ssh/pkg/table"
	"golang.org/x/crypto/ssh"
)

type autostartEntry struct {
	ObserverID string
	Criteria   string
}

var autoStartServerPort = map[internal.RemoteForwardRequest]autostartEntry{}

type listen struct {
	log logger.Logger
}

func (l *listen) server(tty io.ReadWriter, line terminal.ParsedLine, onAddrs, offAddrs []string) error {
	// Handle remove by ID
	if line.IsSet("r") {
		idStr, err := line.GetArgString("id")
		if err != nil {
			return errors.New("remove requires --id, e.g --r --id 1 --server")
		}
		id, err := strconv.Atoi(idStr)
		if err != nil {
			return fmt.Errorf("invalid id: %s", idStr)
		}

		listeners := multiplexer.ServerMultiplexer.GetListeners()
		if id < 1 || id > len(listeners) {
			return fmt.Errorf("server id %d out of range (1-%d)", id, len(listeners))
		}
		addr := listeners[id-1]
		err = multiplexer.ServerMultiplexer.StopListener(addr)
		if err != nil {
			return err
		}
		fmt.Fprintln(tty, "stopped listening on: ", addr)
		return nil
	}

	if line.IsSet("l") {
		listeners := multiplexer.ServerMultiplexer.GetListeners()

		if len(listeners) == 0 {
			fmt.Fprintln(tty, "No active listeners")
			return nil
		}

		t, _ := table.NewTable("Server Listeners", "ID", "Listeners")
		for i, listener := range listeners {
			id := fmt.Sprintf("%d", i+1)
			t.AddValues(id, listener)
		}
		t.Fprint(tty)
		return nil
	}

	for _, addr := range onAddrs {
		err := multiplexer.ServerMultiplexer.StartListener("tcp", addr)
		if err != nil {
			return err
		}
		fmt.Fprintln(tty, "started listening on: ", addr)
	}

	for _, addr := range offAddrs {
		err := multiplexer.ServerMultiplexer.StopListener(addr)
		if err != nil {
			return err
		}
		fmt.Fprintln(tty, "stopped listening on: ", addr)
	}

	return nil
}

func (l *listen) client(user *users.User, tty io.ReadWriter, line terminal.ParsedLine, onAddrs, offAddrs []string) error {

	auto := line.IsSet("auto")
	if line.IsSet("l") && auto {
		for k, v := range autoStartServerPort {
			fmt.Fprintf(tty, "%s %s\n", v.Criteria, net.JoinHostPort(k.BindAddr, fmt.Sprintf("%d", k.BindPort)))
		}
		return nil
	}

	specifier, err := line.GetArgString("c")
	if err != nil {
		specifier, err = line.GetArgString("client")
		if err != nil {
			return err
		}
	}

	foundClients, err := user.SearchClients(specifier)
	if err != nil {
		return err
	}

	if len(foundClients) == 0 && !auto {
		return fmt.Errorf("No clients matched %q", specifier)
	}

	// Handle remove by ID
	if line.IsSet("r") {
		idStr, err := line.GetArgString("id")
		if err != nil {
			return errors.New("remove requires --id, e.g --r --id 1 --client")
		}
		id, err := strconv.Atoi(idStr)
		if err != nil {
			return fmt.Errorf("invalid id: %s", idStr)
		}

		type entry struct {
			clientID    string
			portMapping string
		}

		var entries []entry
		for clientID, cc := range foundClients {
			result, message, _ := cc.SendRequest("query-tcpip-forwards", true, nil)
			if !result {
				fmt.Fprintf(tty, "%s does not support querying server forwards\n", clientID)
				continue
			}

			f := struct {
				RemoteForwards []string
			}{}
			err := ssh.Unmarshal(message, &f)
			if err != nil {
				fmt.Fprintf(tty, "%s sent an incompatible message: %s\n", clientID, err)
				continue
			}

			for _, rf := range f.RemoteForwards {
				entries = append(entries, entry{clientID, rf})
			}
		}

		if id < 1 || id > len(entries) {
			return fmt.Errorf("client id %d out of range (1-%d)", id, len(entries))
		}

		target := entries[id-1]
		ip, port, err := net.SplitHostPort(target.portMapping)
		if err != nil {
			return err
		}
		p, err := strconv.ParseInt(port, 10, 32)
		if err != nil {
			return err
		}

		b := ssh.Marshal(&internal.RemoteForwardRequest{
			BindAddr: ip,
			BindPort: uint32(p),
		})

		applied := 0
		for c, sc := range foundClients {
			result, message, err := sc.SendRequest("cancel-tcpip-forward", true, b)
			if !result {
				fmt.Fprintln(tty, "failed to stop port on: ", c, ": ", string(message))
				continue
			}
			if err != nil {
				fmt.Fprintln(tty, "error stopping port on: ", c, ": ", err)
				continue
			}
			applied++
		}

		fmt.Fprintf(tty, "stopped %s on %d clients\n", target.portMapping, applied)
		return nil
	}

	if line.IsSet("l") {

		t, _ := table.NewTable("Client Listeners", "ID", "Listeners")
		idx := 0
		for id, cc := range foundClients {
			result, message, _ := cc.SendRequest("query-tcpip-forwards", true, nil)
			if !result {
				fmt.Fprintf(tty, "%s does not support querying server forwards\n", id)
				continue
			}

			f := struct {
				RemoteForwards []string
			}{}

			err := ssh.Unmarshal(message, &f)
			if err != nil {
				idx++
				if err := t.AddValues(fmt.Sprintf("%d", idx), id); err != nil {
					return err
				}
				continue
			}

			for _, rf := range f.RemoteForwards {
				idx++
				if err := t.AddValues(fmt.Sprintf("%d", idx), net.JoinHostPort(id, rf)); err != nil {
					return err
				}
			}
		}

		t.Fprint(tty)
		return nil
	}

	var fwRequests []internal.RemoteForwardRequest

	for _, addr := range onAddrs {
		ip, port, err := net.SplitHostPort(addr)
		if err != nil {
			return err
		}

		p, err := strconv.ParseInt(port, 10, 32)
		if err != nil {
			return err
		}

		fwRequests = append(fwRequests, internal.RemoteForwardRequest{
			BindPort: uint32(p),
			BindAddr: ip,
		})

	}

	for _, r := range fwRequests {

		b := ssh.Marshal(&r)

		applied := len(foundClients)
		for c, sc := range foundClients {
			result, message, err := sc.SendRequest("tcpip-forward", true, b)
			if !result {
				applied--
				fmt.Fprintln(tty, "failed to start port on (client may not support it): ", c, ": ", string(message))
				continue
			}

			if err != nil {
				applied--
				fmt.Fprintln(tty, "error starting port on: ", c, ": ", err)
			}
		}

		fmt.Fprintf(tty, "started %s on %d clients (total %d)\n", net.JoinHostPort(r.BindAddr, fmt.Sprintf("%d", r.BindPort)), applied, len(foundClients))

		if auto {
			var entry autostartEntry

			entry.ObserverID = observers.ConnectionState.Register(func(c observers.ClientState) {

				if !user.Matches(specifier, c.ID, c.IP) || c.Status == "disconnected" {
					return
				}

				client, err := user.GetClient(c.ID)
				if err != nil {
					return
				}

				result, message, err := client.SendRequest("tcpip-forward", true, b)
				if !result {
					l.log.Warning("failed to start server tcpip-forward on client: %s: %s", c.ID, message)
					return
				}

				if err != nil {
					l.log.Warning("error auto starting port on: %s: %s", c.ID, err)
					return
				}

			})

			entry.Criteria = specifier

			autoStartServerPort[r] = entry

		}
	}

	var cancelFwRequests []internal.RemoteForwardRequest

	for _, addr := range offAddrs {
		ip, port, err := net.SplitHostPort(addr)
		if err != nil {
			return err
		}

		p, err := strconv.ParseInt(port, 10, 32)
		if err != nil {
			return err
		}

		cancelFwRequests = append(cancelFwRequests, internal.RemoteForwardRequest{
			BindPort: uint32(p),
			BindAddr: ip,
		})

	}

	for _, r := range cancelFwRequests {
		applied := len(foundClients)

		b := ssh.Marshal(&r)
		for c, sc := range foundClients {
			result, message, err := sc.SendRequest("cancel-tcpip-forward", true, b)
			if !result {
				applied--
				fmt.Fprintln(tty, "failed to stop port on: ", c, ": ", string(message))
				continue
			}

			if err != nil {
				applied--
				fmt.Fprintln(tty, "error stop port on: ", c, ": ", err)
			}
		}

		fmt.Fprintf(tty, "stopped %s on %d clients\n", net.JoinHostPort(r.BindAddr, fmt.Sprintf("%d", r.BindPort)), applied)

		if auto {
			if _, ok := autoStartServerPort[r]; ok {
				observers.ConnectionState.Deregister(autoStartServerPort[r].Criteria)
			}
			delete(autoStartServerPort, r)
		}
	}

	return nil
}

func splitAtFirst(s, sep string) []string {
	idx := 0
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			idx = i
			break
		}
	}
	return []string{s[:idx], s[idx+len(sep):]}
}

func (w *listen) ValidArgs() map[string]string {

	r := map[string]string{
		"on":   "Turn on port, e.g --on :8080 127.0.0.1:4444",
		"auto": "Automatically turn on server control port on clients that match criteria, (use --off --auto to disable and --l --auto to view)",
		"off":  "Turn off port, e.g --off :8080 127.0.0.1:4444",
		"l":    "List all enabled addresses",
		"r":    "Remove listener by index id. Requires '--id'",
		"id":   "Listener ID. Requires '-r'",
	}

	addDuplicateFlags("Open server port on client/s takes a pattern, e.g -c *, --client your.hostname.here", r, "client", "c")
	addDuplicateFlags("Change the server listeners", r, "server", "s")

	return r
}

func (w *listen) Run(user *users.User, tty io.ReadWriter, line terminal.ParsedLine) error {

	onAddrs, err := line.GetArgsString("on")
	if err != nil && err != terminal.ErrFlagNotSet {
		return err
	}

	if len(onAddrs) == 0 && err != terminal.ErrFlagNotSet {
		return errors.New("no value specified for --on, requires port e.g --on :4343")
	}

	offAddrs, err := line.GetArgsString("off")
	if err != nil && err != terminal.ErrFlagNotSet {
		return err
	}

	if len(offAddrs) == 0 && err != terminal.ErrFlagNotSet {
		return errors.New("no value specified for --off, requires port e.g --off :4343")
	}

	if onAddrs == nil && offAddrs == nil && !line.IsSet("l") && !line.IsSet("r") {
		return errors.New("no actionable argument supplied, please add --on, --off, -l (list) or -r (remove)")
	}

	if line.IsSet("server") || line.IsSet("s") {
		return w.server(tty, line, onAddrs, offAddrs)
	} else if line.IsSet("client") || line.IsSet("c") || line.IsSet("auto") {
		return w.client(user, tty, line, onAddrs, offAddrs)
	}

	return errors.New("neither server or client were specified, please choose one")
}

func (W *listen) Expect(line terminal.ParsedLine) []string {

	if line.Section != nil {
		switch line.Section.Value() {
		case "c", "client":
			return []string{autocomplete.RemoteId}
		}
	}

	return nil
}

func (w *listen) Help(explain bool) string {
	if explain {
		return "Change, add or stop rssh server port. Open the server port on a client (proxy)"
	}

	return terminal.MakeHelpText(w.ValidArgs(),
		"listen [OPTION] [PORT]",
		"listen starts or stops listening control ports",
		"it allows you to change the servers listening port, or open the servers control port on an rssh client, so that forwarding is easier",
	)
}

func Listen(log logger.Logger) *listen {
	return &listen{
		log: log,
	}
}
