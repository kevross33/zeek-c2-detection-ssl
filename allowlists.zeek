# C2_SSL — allowlists and tuning sets.
#
# Operators redef these in local.zeek to silence known-good infrastructure.
# Defaults cover Microsoft 365, Teams, Exchange, SharePoint, and identity
# infrastructure exhaustively based on the canonical Microsoft endpoint list
# (https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges).

module C2_SSL;

export {
    # ------------------------------------------------------------------
    # Web proxies (explicit / Cisco WSA / Squid / etc).
    # ------------------------------------------------------------------
    #
    # When the responder IP of a TLS connection is a web proxy we cannot
    # trust the IP-level destination — we must use the SNI as the destination
    # identity. We also must NOT use JA3S/JA4S in any per-server tracking,
    # because that fingerprint belongs to the proxy, not the real upstream.
    #
    # Define both a /32 set and a subnet set. Subnets are matched in
    # is_proxy_destination().
    #
    # Add yours: redef C2_SSL::proxy_hosts += { 10.50.0.10, 10.50.0.11 };
    option proxy_hosts: set[addr] = {};
    option proxy_subnets: set[subnet] = {};

    # ------------------------------------------------------------------
    # Proxy TLS mode.
    # ------------------------------------------------------------------
    #
    # PROXY_INTERCEPTING  (default): the proxy terminates TLS and re-signs
    #   with its own CA (SSL-bump / TLS inspection). The certificate,
    #   JA3S/JA4S and validation status on proxied flows belong to the
    #   PROXY, not the real upstream server. The real SNI survives (the
    #   client requested it), and the CONNECT host in http.log — when
    #   present — is authoritative. Because the real server cert is gone,
    #   the detectors must NOT rely on cert signals for proxied flows and
    #   instead lean on behaviour (timing, PCR, destination rarity). This
    #   compensation is applied automatically (see proxy_intercept_*).
    #
    # PROXY_NON_INTERCEPTING: the proxy blindly forwards TLS (CONNECT
    #   tunnel, no inspection). The client does end-to-end TLS with the
    #   real server, so JA3S/JA4S and the certificate chain seen on the
    #   client->proxy leg are REAL. In this mode server fingerprints are
    #   retained and cert signals are used normally.
    #
    # Set to match your deployment:
    #   redef C2_SSL::proxy_mode = C2_SSL::PROXY_NON_INTERCEPTING;
    type ProxyMode: enum { PROXY_INTERCEPTING, PROXY_NON_INTERCEPTING };
    option proxy_mode: ProxyMode = PROXY_INTERCEPTING;

    # ------------------------------------------------------------------
    # Interception CA identification (INTERCEPTING mode).
    # ------------------------------------------------------------------
    #
    # Declare the SSL characteristics of YOUR proxy's interception CA so
    # the module can (a) positively confirm a flow was inspected by your
    # proxy rather than genuinely self-signed C2, and (b) suppress the
    # "self signed / bad validation" signal that your own bump cert would
    # otherwise raise on every proxied flow.
    #
    # Populate whichever you have — matching ANY entry marks the flow as
    # "proxy-intercepted" (trusted interception, not attacker self-signing).
    #
    # proxy_ca_issuers: substring(s) of the certificate issuer DN of your
    #   interception CA. E.g. "CN=Acme SSL Inspection CA".
    #   Substring match, so a distinctive fragment (the CN) is enough.
    #
    # proxy_ca_fingerprints: exact SHA-256 cert fingerprint(s) of your
    #   interception root/intermediate as they appear in x509.log
    #   (cert_chain_fps). Most precise; survives issuer-string spoofing.
    #
    # proxy_ja3s / proxy_ja4s: the server-hello fingerprint(s) your proxy
    #   presents. Because an intercepting proxy re-uses one TLS stack for
    #   all upstreams, its JA3S is IDENTICAL across every destination —
    #   that consistency is itself the tell. Declaring it lets the module
    #   confirm interception even before cert parsing.
    #
    # Example (put real values in local.zeek):
    #   redef C2_SSL::proxy_ca_issuers += { "CN=SJH TLS Inspection CA" };
    #   redef C2_SSL::proxy_ca_fingerprints += { "a1b2c3...ef" };
    #   redef C2_SSL::proxy_ja3s += { "2ab44dd8c27bdce434a961463587356a" };
    option proxy_ca_issuers: set[string] = {};
    option proxy_ca_fingerprints: set[string] = {};
    option proxy_ja3s: set[string] = {};
    option proxy_ja4s: set[string] = {};

    # ------------------------------------------------------------------
    # Trusted DNS suffixes — full bypass.
    # ------------------------------------------------------------------
    #
    # SNIs ending in any of these are fully ignored. Use ONLY for
    # destinations that are infeasible to abuse for C2, primarily
    # Microsoft 365 first-party infrastructure and PKI services.
    #
    # RULE OF THUMB:
    #   - Microsoft 365 first-party services → safe_sni_suffixes (full bypass)
    #   - Abusable CDNs/platforms (Azure FD, Cloudflare Workers, Dropbox) →
    #     trusted_pivot_suffixes (still tracked for JA3 rarity)
    #
    # Microsoft 365 suffixes are sourced from the canonical endpoint list:
    # https://aka.ms/o365endpointwebservice
    option safe_sni_suffixes: set[string] = {

        # ---------------------------------------------------------------
        # Microsoft 365 Unified Domains (ID 184)
        # Purpose-managed, dedicated Microsoft SaaS domains.
        # Cannot be registered by third parties — safe to bypass entirely.
        # ---------------------------------------------------------------
        ".cloud.microsoft",
        ".static.microsoft",
        ".usercontent.microsoft",

        # ---------------------------------------------------------------
        # Exchange Online (IDs 1, 2, 8, 9, 10)
        # ---------------------------------------------------------------
        ".outlook.com",               # *.outlook.com + outlook.cloud.microsoft
        ".office365.com",             # outlook.office365.com, smtp.office365.com etc.
        ".protection.outlook.com",    # EOP/Defender MX/spam filtering
        ".mail.protection.outlook.com",
        ".mx.microsoft",              # New consolidated MX domain

        # ---------------------------------------------------------------
        # SharePoint Online and OneDrive for Business (IDs 31, 37, 39, 75)
        # ---------------------------------------------------------------
        ".sharepoint.com",            # *.sharepoint.com — tenant SPO
        ".sharepointonline.com",      # *.sharepointonline.com CDN/static
        ".svc.ms",                    # *.svc.ms — SPO service endpoints

        # ---------------------------------------------------------------
        # Microsoft Teams and Skype for Business Online (IDs 12, 27, 127)
        # Teams uses *.lync.com infrastructure for signalling.
        # ---------------------------------------------------------------
        ".lync.com",                  # *.lync.com — Teams/SfB signalling
        ".teams.microsoft.com",       # *.teams.microsoft.com
        ".teams.cloud.microsoft",     # *.teams.cloud.microsoft (new unified domain)
        ".skype.com",                 # *.skype.com — consumer Skype and Teams STUN/TURN
        ".skypeassets.com",           # join.secure.skypeassets.com (meeting join)

        # ---------------------------------------------------------------
        # Microsoft 365 Auth / Identity (IDs 56, 59)
        # Entra ID, MSAL, ADAL, conditional access, SSO.
        # These legitimately beacon very frequently (token refresh, SSO keepalive).
        # ---------------------------------------------------------------
        ".microsoftonline.com",       # *.microsoftonline.com — Entra ID / AAD
        ".microsoftonline-p.com",     # *.microsoftonline-p.com — AAD legacy
        ".microsoftonline-p.net",     # clientconfig.microsoftonline-p.net
        ".msauth.net",                # *.msauth.net — auth flows
        ".msftauth.net",              # *.msftauth.net — auth flows
        ".msauthimages.net",          # *.msauthimages.net
        ".msftauthimages.net",        # *.msftauthimages.net
        ".auth.microsoft.com",        # *.auth.microsoft.com
        ".msidentity.com",            # *.msidentity.com
        ".msftidentity.com",          # *.msftidentity.com
        ".phonefactor.net",           # *.phonefactor.net — MFA
        ".login.microsoftonline.com", # login sub-services
        "login.microsoft.com",        # apex (no leading dot)
        "login.windows.net",
        "graph.microsoft.com",
        "graph.windows.net",
        "enterpriseregistration.windows.net",

        # ---------------------------------------------------------------
        # Office Online / Office Apps (IDs 46, 47, 147, 53, 91)
        # ---------------------------------------------------------------
        ".office.com",                # *.office.com, admin.microsoft.com etc.
        ".office.net",                # *.office.net
        ".officeapps.live.com",       # *.officeapps.live.com
        ".online.office.com",         # *.online.office.com
        ".onenote.com",               # *.onenote.com
        ".office365.com",             # already above, harmless duplicate
        "office.live.com",
        "officeapps.live.com",
        "www.microsoft365.com",
        ".cdn.onenote.net",           # *cdn.onenote.net

        # ---------------------------------------------------------------
        # Microsoft Identity / AAD telemetry (ID 69)
        # ---------------------------------------------------------------
        ".aria.microsoft.com",        # telemetry
        ".events.data.microsoft.com", # telemetry (was in supplied logs, caused noise)

        # ---------------------------------------------------------------
        # Power Platform / Flow / Apps (ID 153)
        # ---------------------------------------------------------------
        ".flow.microsoft.com",
        ".powerapps.com",
        ".powerautomate.com",
        ".azure-apim.net",

        # ---------------------------------------------------------------
        # Rights Management / Information Protection (ID 73)
        # ---------------------------------------------------------------
        ".aadrm.com",
        ".azurerms.com",
        ".informationprotection.azure.com",

        # ---------------------------------------------------------------
        # Microsoft 365 Security & Compliance (ID 64)
        # ---------------------------------------------------------------
        ".protection.office.com",
        ".security.microsoft.com",
        "compliance.microsoft.com",
        "defender.microsoft.com",
        "purview.microsoft.com",

        # ---------------------------------------------------------------
        # Activity / Cortana (IDs 156, 158)
        # ---------------------------------------------------------------
        ".activity.windows.com",
        ".cortana.ai",

        # ---------------------------------------------------------------
        # OneDrive consumer sync client (IDs 35, 36, 53)
        # Distinct from SharePoint Online tenant OneDrive.
        # ---------------------------------------------------------------
        ".wns.windows.com",           # Windows Notification Service
        "admin.onedrive.com",
        "officeclient.microsoft.com",
        "g.live.com",
        "oneclient.sfx.ms",
        "www.onedrive.com",
        "ajax.aspnetcdn.com",

        # ---------------------------------------------------------------
        # Public DNS-over-HTTPS (DoH) resolvers.
        # Firefox, Chrome, Edge and Android all make encrypted DNS queries
        # to these over persistent HTTPS connections. The pattern looks
        # like beaconing (regular intervals, small packets) but is driven
        # by DNS TTL expiry and ALPN is always h2. All legitimate.
        # ---------------------------------------------------------------
        "private.canadianshield.cira.ca",  # CIRA Canadian Shield DoH
        "family.canadianshield.cira.ca",
        "protected.canadianshield.cira.ca",
        "dns.cloudflare.com",              # Cloudflare 1.1.1.1 DoH
        "one.one.one.one",
        "dns.google",                      # Google 8.8.8.8 DoH
        "dns64.dns.google",
        "doh.opendns.com",                 # OpenDNS DoH
        "doh.familyshield.opendns.com",
        "dns.quad9.net",                   # Quad9 DoH
        "dns10.quad9.net",
        "dns11.quad9.net",
        "doh.cleanbrowsing.org",           # CleanBrowsing DoH
        "security-filter-dns.cleanbrowsing.org",
        "doh.sb",                          # DNS.SB DoH
        ".doh.mullvad.net",                # Mullvad DoH

        # ---------------------------------------------------------------
        # Google infrastructure — push notifications, telemetry, APIs.
        # These create long-lived TLS connections with tiny keepalive
        # packets (Android FCM, Chrome push, GCM) that look like C2
        # tunnels to a naive traffic analyser.
        # ---------------------------------------------------------------
        ".google.com",                # *.google.com — search, APIs, auth
        ".googleapis.com",            # *.googleapis.com — GCP APIs
        ".gvt2.com",                  # beacons.gvt2.com — Chrome update beacon
        ".gvt1.com",                  # redirector.gvt1.com — CDN
        ".gstatic.com",               # *.gstatic.com — static assets
        ".googlevideo.com",           # *.googlevideo.com — YouTube CDN
        ".googleusercontent.com",     # user content (moved from pivot)
        ".ggpht.com",                 # app icons
        ".1e100.net",                 # Google server reverse DNS
        ".android.com",               # *.android.com
        "android.apis.google.com",    # FCM / push channel (apex + sub)
        ".clients.google.com",        # clients1-4.google.com
        ".mtalk.google.com",          # GCM/FCM XMPP (port 5228 but sometimes 443)

        # ---------------------------------------------------------------
        # Microsoft Edge / Windows telemetry domains.
        # edge.microsoft.com produces long-lived h2 keepalive sockets.
        # ---------------------------------------------------------------
        "edge.microsoft.com",         # Edge browser update / config
        ".edge.microsoft.com",
        "config.edge.skype.com",      # Edge / Teams config (already in Teams block above)
        ".telecommand.telemetry.microsoft.com",
        ".settings-win.data.microsoft.com",
        "apis.live.net",

        # ---------------------------------------------------------------
        # Office CDN / Updates (IDs 83, 84, 86, 89, 91, 92)
        # ---------------------------------------------------------------
        "activation.sls.microsoft.com",
        "crl.microsoft.com",
        "mscrl.microsoft.com",
        "office15client.microsoft.com",
        "go.microsoft.com",
        "officecdn.microsoft.com",
        "aka.ms",

        # ---------------------------------------------------------------
        # PKI infrastructure — CRL, OCSP, CA certs.
        # (extends the existing list; ID 125 from M365 endpoint data)
        # ---------------------------------------------------------------
        ".windowsupdate.com",
        ".update.microsoft.com",
        ".windowsupdate.microsoft.com",
        ".dl.delivery.mp.microsoft.com",
        ".do.dsp.mp.microsoft.com",
        ".tlu.dl.delivery.mp.microsoft.com",
        ".wustat.windows.com",
        ".pki.goog",
        ".symantec.com",
        ".digicert.com",
        ".verisign.com",
        ".verisign.net",
        ".sectigo.com",
        ".letsencrypt.org",
        ".ocsp.entrust.net",
        ".entrust.net",
        ".geotrust.com",
        ".omniroot.com",
        ".public-trust.com",
        ".symcb.com",
        ".symcd.com",
        ".identrust.com",
        ".globalsign.com",
        ".globalsign.net",
        ".crl3.digicert.com",
        ".crl4.digicert.com",
        ".ocsp.sectigo.com",
        ".lencr.org",
        "ocsp.msocsp.com",
        "oneocsp.microsoft.com",
        "secure.globalsign.com",

        # ---------------------------------------------------------------
        # Major enterprise vendor infrastructure — first-party telemetry,
        # update, management, and collaboration services. These are
        # broadly present in enterprise networks and carry
        # low C2-abuse risk on their own apex/vendor domains.
        # ---------------------------------------------------------------
        # Cisco (Webex, DNA Center, corporate services, Secure Access/SIG).
        ".cisco.com",
        ".webex.com",
        ".ciscodna.com",
        ".ciscoconnectdna.com",
        # Azure first-party monitoring / security telemetry.
        ".opinsights.azure.com",       # Azure Monitor / Log Analytics (MMA/OMS)
        ".atp.azure.com",              # Defender for Identity (Azure ATP)
        ".servicebus.windows.net",     # Azure Service Bus relay/messaging
        # Endpoint / infrastructure vendors.
        ".dell.com",                   # Dell SupportAssist / update telemetry
        ".redhat.com",                 # RHSM, Red Hat Insights, updates
        ".ecostruxureit.com",          # Schneider EcoStruxure (BMS/DCIM/energy)
        # Adobe API / service endpoints.
        ".adobe.io",
        ".adobess.com",
    };

    # ------------------------------------------------------------------
    # Trusted-pivot hosts — abusable but legitimate.
    # ------------------------------------------------------------------
    #
    # These are NOT bypassed. Connections here still get full
    # beacon/tunnel analysis AND are checked for fingerprint rarity
    # (i.e. "is this client the only client in the network using this
    # JA3 against this host?"). That's how we catch backend C2 hidden
    # behind Azure Front Door, Dropbox, Cloudflare Workers, etc.
    #
    # Note: *.sharepoint.com and *.onedrive.live.com (consumer) are
    # distinct: SPO (*.sharepoint.com) is in safe_sni_suffixes because
    # it is a dedicated tenant-domain service. Consumer OneDrive
    # *.onedrive.live.com remains here because raw blob access can be
    # used for C2 staging in a way that SNI-safe SPO cannot.
    option trusted_pivot_suffixes: set[string] = {
        # Azure CDN / fronting (abusable for domain-fronting C2)
        ".azureedge.net",
        ".azurefd.net",
        ".trafficmanager.net",
        # Cloudflare
        ".cloudfront.net",
        ".cloudflare.com",
        ".cloudflare.net",
        ".workers.dev",
        ".pages.dev",
        # Other CDNs
        ".fastly.net",
        ".akamaized.net",
        ".akamaiedge.net",
        # File-sharing / blob storage (raw blob C2 staging)
        ".dropbox.com",
        ".dropboxusercontent.com",
        ".onedrive.live.com",         # Consumer OneDrive (NOT SPO)
        ".box.com",
        ".googleusercontent.com",
        ".storage.googleapis.com",
        ".s3.amazonaws.com",
        ".blob.core.windows.net",     # Azure Blob — common C2 staging
        # Code hosting
        ".githubusercontent.com",
        ".raw.githubusercontent.com",
        ".gitlab.io",
        # Pastes / public content
        ".pastebin.com",
        ".github.io",
        # Comms platforms with webhook/bot abuse
        ".discord.com",
        ".discordapp.com",
        ".slack.com",
        ".telegram.org",
    };

    # ------------------------------------------------------------------
    # Suspicious certificate issuer fragments.
    # ------------------------------------------------------------------
    #
    # Substring matches against the certificate issuer string. Hits add a
    # confidence bump but do not alert on their own. Combined with beaconing
    # or tunnel indicators they are strongly indicative of custom tooling.
    option suspect_cert_issuers: set[string] = {
        "Internet Widgits Pty Ltd",   # OpenSSL default — extremely common in C2
        "CN=localhost",
        "Acme Co",                    # Go crypto/tls test cert default (Cobalt Strike)
        "Default Company Ltd",
        "snakeoil",
        "/CN=Default",
        "Test CA",
        "Metasploit",
        "msf",
        "My Company Ltd",             # Another Go default
    };

    # ------------------------------------------------------------------
    # Trusted internal subnets — never alert on these as originators.
    # ------------------------------------------------------------------
    #
    # Medical devices, franking machines, printers — anything that legitimately
    # beacons to vendor cloud. Operators MUST populate this per-site.
    #
    # Example:
    #   redef C2_SSL::trusted_orig_subnets += {
    #       10.40.0.0/16,   # Medical imaging VLAN
    #       10.41.0.0/16,   # Lab analyser VLAN
    #       10.99.5.0/24,   # Franking machines
    #   };
    option trusted_orig_subnets: set[subnet] = {};

    # Individual trusted originator IPs (convenience — same effect as a /32
    # in trusted_orig_subnets, but clearer for one-off hosts).
    #   redef C2_SSL::trusted_orig_hosts += { 10.12.7.50, 10.12.7.51 };
    option trusted_orig_hosts: set[addr] = {};

    # ------------------------------------------------------------------
    # Trusted destination subnets — internal management traffic.
    # ------------------------------------------------------------------
    #
    # Anything terminating inside these is bypassed (jump servers,
    # internal CAs, monitoring infrastructure, vCenter, etc.).
    # By default empty — lateral C2 is in scope, so do not bypass RFC1918
    # broadly. Add narrowly.
    option trusted_dest_subnets: set[subnet] = {};

    # Individual trusted destination IPs (convenience — same effect as a
    # /32 in trusted_dest_subnets). Use for specific known-good external
    # endpoints that would otherwise look beacon-shaped (e.g. a licence
    # server, a specific vendor telemetry IP without a stable SNI).
    #   redef C2_SSL::trusted_dest_hosts += { 203.0.113.10 };
    option trusted_dest_hosts: set[addr] = {};

    # ------------------------------------------------------------------
    # Helper predicates.
    # ------------------------------------------------------------------

    # True if the responder IP is a configured web proxy.
    global is_proxy_destination: function(a: addr): bool;

    # True if SNI ends in any safe_sni_suffix (full bypass).
    global is_sni_fully_safe: function(sni: string): bool;

    # True if SNI ends in any trusted_pivot_suffix (still tracked).
    global is_sni_trusted_pivot: function(sni: string): bool;

    # True if originator is in a trusted-orig subnet.
    global is_orig_trusted: function(a: addr): bool;

    # True if destination is in a trusted-dest subnet.
    global is_dest_trusted: function(a: addr): bool;

    # True if the address is internal (Site::local_nets or c2_internal_nets).
    global is_internal_addr: function(a: addr): bool;

    # True if the connection is outbound (internal client -> external server),
    # honouring c2_analyse_east_west. Used to scope detection to outbound C2.
    global is_outbound_flow: function(c: connection): bool;

    # True if any suspect_cert_issuer fragment appears in the issuer string.
    global has_suspect_issuer: function(issuer: string): bool;

    # True if the cert issuer matches a declared interception CA issuer.
    global is_proxy_ca_issuer: function(issuer: string): bool;

    # True if any fingerprint in the (comma-joined) cert_chain_fps matches
    # a declared interception CA fingerprint.
    global is_proxy_ca_fingerprint: function(fps: string): bool;

    # True if a JA3S/JA4S matches the declared proxy server fingerprints.
    global is_proxy_server_fp: function(ja3s: string, ja4s: string): bool;
}

function is_proxy_ca_issuer(issuer: string): bool
    {
    if ( issuer == "" ) return F;
    for ( frag in proxy_ca_issuers )
        if ( frag in issuer )
            return T;
    return F;
    }

function is_proxy_ca_fingerprint(fps: string): bool
    {
    if ( fps == "" || fps == "-" ) return F;
    for ( fp in proxy_ca_fingerprints )
        if ( fp in fps )
            return T;
    return F;
    }

function is_proxy_server_fp(ja3s: string, ja4s: string): bool
    {
    if ( ja3s != "" && ja3s != "-" && ja3s in proxy_ja3s )
        return T;
    if ( ja4s != "" && ja4s != "-" && ja4s in proxy_ja4s )
        return T;
    return F;
    }

function is_proxy_destination(a: addr): bool
    {
    if ( a in proxy_hosts )
        return T;
    for ( s in proxy_subnets )
        if ( a in s )
            return T;
    return F;
    }

function sni_ends_with_any(sni: string, suffixes: set[string]): bool
    {
    if ( sni == "" || sni == "(empty)" )
        return F;
    local lc = to_lower(sni);
    for ( suffix in suffixes )
        {
        # Match ".suffix" at end of hostname, e.g. ".lync.com" matches
        # "contoso.lync.com" and also "lync.com" (apex match).
        if ( |lc| >= |suffix| )
            {
            local tail = lc[|lc| - |suffix|:];
            if ( tail == suffix )
                return T;
            }
        # Apex match: "login.microsoft.com" against suffix "login.microsoft.com"
        # (stored without leading dot for exact apexes).
        if ( |suffix| > 0 && suffix[0:1] != "." && lc == suffix )
            return T;
        # Also match apex when suffix stored with leading dot: strip it.
        if ( |suffix| > 1 && lc == suffix[1:] )
            return T;
        }
    return F;
    }

function is_sni_fully_safe(sni: string): bool
    {
    return sni_ends_with_any(sni, safe_sni_suffixes);
    }

function is_sni_trusted_pivot(sni: string): bool
    {
    return sni_ends_with_any(sni, trusted_pivot_suffixes);
    }

function is_orig_trusted(a: addr): bool
    {
    if ( a in trusted_orig_hosts )
        return T;
    for ( s in trusted_orig_subnets )
        if ( a in s )
            return T;
    return F;
    }

function is_dest_trusted(a: addr): bool
    {
    if ( a in trusted_dest_hosts )
        return T;
    for ( s in trusted_dest_subnets )
        if ( a in s )
            return T;
    return F;
    }

# is_internal_addr — is this address part of our estate? True if it is in
# Zeek's Site::local_nets (operator-configured) OR our c2_internal_nets set
# (RFC1918/CGNAT defaults). Using both means the direction filter works
# whether or not the sensor has local_nets configured.
function is_internal_addr(a: addr): bool
    {
    if ( Site::is_local_addr(a) )
        return T;
    for ( s in c2_internal_nets )
        if ( a in s )
            return T;
    return F;
    }

# is_outbound_flow — does this connection go from an internal client to an
# external server? This package's scope is OUTBOUND C2 egress from
# compromised internal hosts. Inbound (external->internal) flows such as RDP
# brute-force are out of scope and dropped. East-west (internal->internal) is
# also dropped unless c2_analyse_east_west is set.
function is_outbound_flow(c: connection): bool
    {
    local orig_internal = is_internal_addr(c$id$orig_h);
    local resp_internal = is_internal_addr(c$id$resp_h);

    # Originator must be internal — we only care about our own hosts calling
    # out. An external originator is inbound, out of scope.
    if ( ! orig_internal )
        return F;

    # Responder external => outbound (in scope).
    if ( ! resp_internal )
        return T;

    # Both internal => east-west. In scope only if explicitly enabled.
    return c2_analyse_east_west;
    }

function has_suspect_issuer(issuer: string): bool
    {
    if ( issuer == "" )
        return F;
    for ( frag in suspect_cert_issuers )
        if ( frag in issuer )
            return T;
    return F;
    }
