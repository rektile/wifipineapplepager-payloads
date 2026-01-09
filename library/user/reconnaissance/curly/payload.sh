#!/bin/bash
# Title: Curly - Web Recon & Vuln Scanner
# Description: Curl-based web reconnaissance and vulnerability testing for pentesting and bug bounty hunting
# Author: curtthecoder
# Version: 3.1

# === CONFIG ===
LOOTDIR=/root/loot/curly
INPUT=/dev/input/event0
TIMEOUT=10

# === CLEANUP ===
cleanup() {
    led_off 2>/dev/null
    dd if=$INPUT of=/dev/null bs=16 count=200 iflag=nonblock 2>/dev/null
    sleep 0.2
}

trap cleanup EXIT INT TERM

# === LED CONTROL ===
led_pattern() {
    . /lib/hak5/commands.sh
    HAK5_API_POST "system/led" "$1" >/dev/null 2>&1
}

led_off() {
    led_pattern '{"color":"custom","raw_pattern":[{"onms":100,"offms":0,"next":false,"rgb":{"1":[false,false,false],"2":[false,false,false],"3":[false,false,false],"4":[false,false,false]}}]}'
}

led_scanning() {
    led_pattern '{"color":"custom","raw_pattern":[{"onms":500,"offms":500,"next":true,"rgb":{"1":[false,false,true],"2":[false,false,true],"3":[false,false,false],"4":[false,false,false]}},{"onms":500,"offms":0,"next":false,"rgb":{"1":[false,false,false],"2":[false,false,false],"3":[false,false,false],"4":[false,false,false]}}]}'
}

led_found() {
    led_pattern '{"color":"custom","raw_pattern":[{"onms":2000,"offms":0,"next":false,"rgb":{"1":[true,false,false],"2":[true,false,false],"3":[true,false,false],"4":[true,false,false]}}]}'
}

led_success() {
    led_pattern '{"color":"custom","raw_pattern":[{"onms":2000,"offms":0,"next":false,"rgb":{"1":[false,true,false],"2":[false,true,false],"3":[false,true,false],"4":[false,true,false]}}]}'
}

# === SOUNDS ===
play_scan() { RINGTONE "scan:d=4,o=5,b=180:c,e,g" & }
play_found() { RINGTONE "found:d=8,o=6,b=200:c,e,g,c7" & }
play_complete() { RINGTONE "xp" & }

# === CORE FUNCTIONS ===

# Initialize loot directory
init_loot() {
    mkdir -p "$LOOTDIR"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    LOOTFILE="$LOOTDIR/${TARGET_HOST}_${TIMESTAMP}.txt"
    echo "=== CURLY WEB RECON SCAN ===" > "$LOOTFILE"
    echo "Target: $TARGET_URL" >> "$LOOTFILE"
    echo "Date: $(date)" >> "$LOOTFILE"
    echo "================================" >> "$LOOTFILE"
    echo "" >> "$LOOTFILE"
}

# Log to both screen and file
log_result() {
    local msg="$1"
    echo "$msg" >> "$LOOTFILE"
    LOG "$msg"
}

# Extract base info from URL
parse_url() {
    local url="$1"
    # Remove protocol
    TARGET_HOST=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1 | cut -d':' -f1)
    TARGET_PROTO=$(echo "$url" | grep -q "https://" && echo "https" || echo "http")
}

# Follow redirects to get final URL
follow_redirects() {
    LOG "Following redirects..."
    # Use -I for HEAD request, -L to follow redirects, get final URL
    local final_url=$(curl -sIL -m $TIMEOUT "$TARGET_URL" 2>/dev/null | grep -i "^location:" | tail -1 | cut -d' ' -f2 | tr -d '\r')

    if [ -n "$final_url" ]; then
        # Update to final destination
        LOG "Redirect detected: $final_url"

        # Check if redirect is relative (starts with /)
        if [[ "$final_url" =~ ^/ ]]; then
            # Relative redirect - prepend original protocol and host
            TARGET_URL="${TARGET_PROTO}://${TARGET_HOST}${final_url}"
            LOG "Relative redirect resolved to: $TARGET_URL"
        else
            # Absolute redirect
            TARGET_URL="$final_url"
            parse_url "$TARGET_URL"
            TARGET_URL="${TARGET_PROTO}://${TARGET_HOST}"
            LOG "Updated target: $TARGET_URL"
        fi
    fi
}

# === SCAN MODULES ===

# 0. IP Geolocation Lookup
scan_ip_geolocation() {
    log_result "[+] IP GEOLOCATION LOOKUP"
    led_scanning

    # Resolve domain to IP
    LOG "Resolving IP address..."
    local target_ip=$(nslookup "$TARGET_HOST" 2>/dev/null | grep -A1 "Name:" | grep "Address:" | tail -1 | awk '{print $2}')

    # Fallback method if nslookup format differs
    if [ -z "$target_ip" ]; then
        target_ip=$(host "$TARGET_HOST" 2>/dev/null | grep "has address" | head -1 | awk '{print $4}')
    fi

    if [ -z "$target_ip" ]; then
        log_result "[*] Could not resolve IP address"
        log_result ""
        return
    fi

    log_result "[*] Target IP: $target_ip"

    # Query ipinfo.io
    LOG "Querying ipinfo.io..."
    local ipinfo=$(curl -s -m $TIMEOUT "https://ipinfo.io/${target_ip}/json" 2>/dev/null)

    if [ -z "$ipinfo" ]; then
        log_result "[*] Could not retrieve IP info"
        log_result ""
        return
    fi

    # Parse JSON fields (bash-friendly parsing)
    local hostname=$(echo "$ipinfo" | grep -o '"hostname"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    local city=$(echo "$ipinfo" | grep -o '"city"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    local region=$(echo "$ipinfo" | grep -o '"region"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    local country=$(echo "$ipinfo" | grep -o '"country"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    local loc=$(echo "$ipinfo" | grep -o '"loc"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    local org=$(echo "$ipinfo" | grep -o '"org"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    local postal=$(echo "$ipinfo" | grep -o '"postal"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    local timezone=$(echo "$ipinfo" | grep -o '"timezone"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)

    # Format output nicely
    log_result ""
    log_result "━━━ IP Information ━━━"
    [ -n "$hostname" ] && log_result "  Hostname    : $hostname"
    [ -n "$city" ] && [ -n "$region" ] && log_result "  Location    : $city, $region"
    [ -n "$country" ] && log_result "  Country     : $country"
    [ -n "$postal" ] && log_result "  Postal Code : $postal"
    [ -n "$loc" ] && log_result "  Coordinates : $loc"
    [ -n "$org" ] && log_result "  Organization: $org"
    [ -n "$timezone" ] && log_result "  Timezone    : $timezone"
    log_result "━━━━━━━━━━━━━━━━━━━━━━"

    log_result ""
}

# 1. Information Gathering
scan_info() {
    log_result "[+] INFORMATION GATHERING"
    led_scanning

    # Get headers
    log_result "--- Response Headers ---"
    curl -sI -m $TIMEOUT "$TARGET_URL" 2>/dev/null | tee -a "$LOOTFILE" | head -5 | while read line; do LOG "$line"; done

    # Check for security headers
    log_result ""
    log_result "--- Security Headers Check ---"
    local headers=$(curl -sI -m $TIMEOUT "$TARGET_URL" 2>/dev/null)

    [ -z "$(echo "$headers" | grep -i 'X-Frame-Options')" ] && log_result "[!] Missing: X-Frame-Options" && play_found
    [ -z "$(echo "$headers" | grep -i 'X-Content-Type-Options')" ] && log_result "[!] Missing: X-Content-Type-Options" && play_found
    [ -z "$(echo "$headers" | grep -i 'Strict-Transport-Security')" ] && log_result "[!] Missing: HSTS" && play_found
    [ -z "$(echo "$headers" | grep -i 'Content-Security-Policy')" ] && log_result "[!] Missing: CSP" && play_found

    # Server fingerprinting
    local server=$(echo "$headers" | grep -i "^Server:" | cut -d':' -f2- | tr -d '\r')
    [ -n "$server" ] && log_result "[*] Server:$server" && play_found

    local powered=$(echo "$headers" | grep -i "^X-Powered-By:" | cut -d':' -f2- | tr -d '\r')
    [ -n "$powered" ] && log_result "[!] X-Powered-By:$powered" && play_found

    log_result ""
}

# 2. Enhanced Endpoints Discovery
scan_endpoints() {
    log_result "[+] ENHANCED ENDPOINTS DISCOVERY"
    led_scanning

    local endpoints=(
        # Common files
        "/robots.txt"
        "/sitemap.xml"
        "/.git/config"
        "/.git/HEAD"
        "/.git/index"
        "/.svn/entries"
        "/.hg/"
        "/.env"
        "/.aws/credentials"
        "/phpinfo.php"
        "/.well-known/security.txt"
        # Admin & Auth
        "/admin"
        "/admin.php"
        "/administrator"
        "/login"
        "/console"
        # API endpoints
        "/api"
        "/api/v1"
        "/api/v2"
        "/api/docs"
        "/swagger.json"
        "/swagger-ui.html"
        "/openapi.json"
        "/graphql"
        "/graphiql"
        # Spring Boot Actuator
        "/actuator"
        "/actuator/env"
        "/actuator/health"
        "/actuator/metrics"
        "/actuator/mappings"
        "/actuator/trace"
        # Debug & Monitoring
        "/debug"
        "/trace"
        "/metrics"
        "/health"
        "/status"
        "/info"
        # Laravel
        "/telescope"
        # Django
        "/__debug__/"
        # Tomcat
        "/manager/html"
        "/manager/status"
    )

    LOG "Checking ${#endpoints[@]} endpoints..."
    local found=0

    for endpoint in "${endpoints[@]}"; do
        local url="${TARGET_PROTO}://${TARGET_HOST}${endpoint}"
        local status=$(curl -s -o /dev/null -w "%{http_code}" -m $TIMEOUT "$url" 2>/dev/null)

        if [ "$status" = "200" ]; then
            # Status 200 - Found! Beep and alert
            log_result "[!] FOUND [$status]: $endpoint"
            found=$((found + 1))
            play_found
            led_found
            sleep 0.3
        elif [ "$status" = "301" ] || [ "$status" = "302" ]; then
            # Redirects - Log but don't beep
            log_result "[*] REDIRECT [$status]: $endpoint"
            found=$((found + 1))
        fi
        sleep 0.05
    done

    if [ $found -eq 0 ]; then
        log_result "[*] No endpoints found"
    fi

    log_result ""
}

# 3. HTTP Methods Testing
scan_methods() {
    log_result "[+] HTTP METHODS TESTING"
    led_scanning

    local methods=("OPTIONS" "PUT" "DELETE" "TRACE" "PATCH")
    local found_vuln=0
    local rate_limited=0

    LOG "Testing ${#methods[@]} HTTP methods..."

    for method in "${methods[@]}"; do
        local status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" -m $TIMEOUT "$TARGET_URL" 2>/dev/null)

        case "$status" in
            200|201|204)
                # Actually allowed - this is a real issue!
                log_result "[!] $method ENABLED: HTTP $status"
                play_found
                led_found
                found_vuln=1
                sleep 0.3
                ;;
            429|503)
                # Rate limited or service unavailable
                log_result "[-] $method rate limited: HTTP $status"
                rate_limited=1
                ;;
            405|501)
                # Properly blocked - this is good (405=Not Allowed, 501=Not Implemented)
                # Don't log these, they're secure
                ;;
            000)
                # Timeout - don't log
                ;;
            *)
                # Other status codes - might be interesting
                log_result "[?] $method unexpected: HTTP $status"
                ;;
        esac
        sleep 0.1
    done

    if [ $found_vuln -eq 0 ] && [ $rate_limited -eq 0 ]; then
        log_result "[*] All methods properly blocked"
    elif [ $found_vuln -eq 0 ] && [ $rate_limited -eq 1 ]; then
        log_result "[*] No unsafe methods detected (some rate limited)"
    fi

    log_result ""
}

# 4. Header Injection Tests
scan_headers() {
    log_result "[+] HEADER INJECTION TESTS"
    led_scanning

    # X-Forwarded-For
    local xff_resp=$(curl -s -m $TIMEOUT -H "X-Forwarded-For: 127.0.0.1" "$TARGET_URL" 2>/dev/null)
    if echo "$xff_resp" | grep -q "127.0.0.1"; then
        log_result "[!] X-Forwarded-For may be reflected"
        play_found
    fi

    # Host header
    local host_status=$(curl -s -o /dev/null -w "%{http_code}" -m $TIMEOUT -H "Host: evil.com" "$TARGET_URL" 2>/dev/null)
    if [ "$host_status" = "200" ]; then
        log_result "[!] Host header accepted: evil.com"
        play_found
    fi

    # X-Original-URL bypass attempt
    local bypass_status=$(curl -s -o /dev/null -w "%{http_code}" -m $TIMEOUT -H "X-Original-URL: /admin" "$TARGET_URL" 2>/dev/null)
    if [ "$bypass_status" = "200" ]; then
        log_result "[!] X-Original-URL bypass possible"
        play_found
        led_found
    fi

    log_result ""
}

# 5. CORS Misconfiguration
scan_cors() {
    log_result "[+] CORS MISCONFIGURATION CHECK"
    led_scanning

    LOG "Testing CORS policy..."
    local cors=$(curl -s -m $TIMEOUT -H "Origin: https://evil.com" -I "$TARGET_URL" 2>/dev/null | grep -i "Access-Control-Allow-Origin")

    if echo "$cors" | grep -q "evil.com"; then
        log_result "[!] CORS reflects arbitrary origin!"
        play_found
        led_found
    elif echo "$cors" | grep -q "*"; then
        log_result "[!] CORS allows wildcard (*)"
        play_found
    else
        log_result "[*] No CORS issues detected"
    fi

    log_result ""
}

# 6. Redirect & SSRF Tests
scan_redirects() {
    log_result "[+] REDIRECT & SSRF TESTS"
    led_scanning

    # Test common redirect parameters
    local params=("url" "redirect" "next" "return" "dest" "destination" "redir" "redirect_uri")
    local found=0

    LOG "Testing ${#params[@]} redirect params..."
    for param in "${params[@]}"; do
        local test_url="${TARGET_URL}?${param}=https://evil.com"
        local location=$(curl -s -m $TIMEOUT -I "$test_url" 2>/dev/null | grep -i "^Location:" | cut -d' ' -f2 | tr -d '\r')

        if [ -n "$location" ]; then
            # Extract the redirect destination (the actual domain being redirected TO)
            # Check if it starts with http:// or https:// followed by evil.com
            if echo "$location" | grep -qE '^https?://evil\.com(/|$)'; then
                log_result "[!] Open redirect via: $param"
                log_result "    Redirects to: $location"
                play_found
                led_found
                found=1
                sleep 0.5
            elif echo "$location" | grep -qE '^//evil\.com(/|$)'; then
                # Protocol-relative URL (//evil.com)
                log_result "[!] Open redirect via: $param"
                log_result "    Redirects to: $location"
                play_found
                led_found
                found=1
                sleep 0.5
            fi
        fi
    done

    if [ $found -eq 0 ]; then
        log_result "[*] No open redirects found"
    fi

    log_result ""
}

# 7. API Testing
scan_api() {
    log_result "[+] API ENDPOINT TESTING"
    led_scanning

    local api_endpoints=(
        "/api"
        "/api/v1/users"
        "/api/v1/config"
        "/api/v1/admin"
        "/api/debug"
        "/api/swagger"
        "/v1/graphql"
    )

    LOG "Checking ${#api_endpoints[@]} API endpoints..."
    local found=0

    for endpoint in "${api_endpoints[@]}"; do
        local url="${TARGET_PROTO}://${TARGET_HOST}${endpoint}"
        local resp=$(curl -s -m $TIMEOUT "$url" 2>/dev/null)
        local status=$(curl -s -o /dev/null -w "%{http_code}" -m $TIMEOUT "$url" 2>/dev/null)

        if [ "$status" = "200" ]; then
            log_result "[!] API FOUND [$status]: $endpoint"
            found=1
            # Check for sensitive data
            if echo "$resp" | grep -qE '(password|secret|key|token|api_key)'; then
                log_result "[!!!] Possible sensitive data in response!"
                play_found
                led_found
                sleep 0.5
            fi
        fi
        sleep 0.1
    done

    if [ $found -eq 0 ]; then
        log_result "[*] No API endpoints found"
    fi

    log_result ""
}

# 8. Backup File Hunter
scan_backups() {
    log_result "[+] BACKUP FILE HUNTER"
    led_scanning

    # Common backup extensions and patterns
    local base_files=("index" "config" "database" "db" "backup" "admin" "login" "wp-config")
    local extensions=(".bak" ".old" ".backup" "~" ".save" ".copy" ".orig" ".sql" ".tar.gz" ".zip")
    local found=0

    LOG "Hunting for backup files..."

    for base in "${base_files[@]}"; do
        for ext in "${extensions[@]}"; do
            local file="${base}${ext}"
            local url="${TARGET_PROTO}://${TARGET_HOST}/${file}"

            # Get both status and content-type to avoid false positives from redirects
            local response=$(curl -s -I -m $TIMEOUT "$url" 2>/dev/null)
            local status=$(echo "$response" | head -1 | grep -o "[0-9]\{3\}")
            local content_type=$(echo "$response" | grep -i "^content-type:" | cut -d':' -f2 | tr -d ' \r')

            # Only flag if 200 AND not HTML (backup files shouldn't be HTML)
            if [ "$status" = "200" ]; then
                # Ignore if it's HTML (likely a redirect to main page)
                if ! echo "$content_type" | grep -qi "text/html"; then
                    log_result "[!] BACKUP FOUND: /$file (${content_type})"
                    play_found
                    led_found
                    found=1
                    sleep 0.3
                fi
            fi
        done
    done

    if [ $found -eq 0 ]; then
        log_result "[*] No backup files found"
    fi

    log_result ""
}

# 9. Cookie Security Analysis
scan_cookies() {
    log_result "[+] COOKIE SECURITY ANALYSIS"
    led_scanning

    LOG "Analyzing cookies..."
    local cookies=$(curl -s -I -m $TIMEOUT "$TARGET_URL" 2>/dev/null | grep -i "^Set-Cookie:")

    if [ -z "$cookies" ]; then
        log_result "[*] No cookies set"
    else
        log_result "[*] Cookies detected, analyzing..."
        local cookie_count=$(echo "$cookies" | wc -l | tr -d ' ')
        log_result "[*] Found $cookie_count cookie(s)"

        # Check each cookie for security flags
        while IFS= read -r cookie; do
            local cookie_name=$(echo "$cookie" | sed 's/Set-Cookie: //' | cut -d'=' -f1 | tr -d '\r')

            # Check for HttpOnly flag
            if ! echo "$cookie" | grep -qi "HttpOnly"; then
                log_result "[!] Cookie '$cookie_name' missing HttpOnly flag"
                play_found
            fi

            # Check for Secure flag
            if ! echo "$cookie" | grep -qi "Secure"; then
                log_result "[!] Cookie '$cookie_name' missing Secure flag"
                play_found
            fi

            # Check for SameSite
            if ! echo "$cookie" | grep -qi "SameSite"; then
                log_result "[!] Cookie '$cookie_name' missing SameSite flag"
            fi
        done <<< "$cookies"
    fi

    log_result ""
}

# 10. WAF/CDN Detection
scan_waf() {
    log_result "[+] WAF/CDN DETECTION"
    led_scanning

    LOG "Detecting protection..."
    local headers=$(curl -s -I -m $TIMEOUT "$TARGET_URL" 2>/dev/null)
    local found_waf=0

    # Cloudflare
    if echo "$headers" | grep -qi "cloudflare\|cf-ray"; then
        log_result "[*] WAF: Cloudflare detected"
        found_waf=1
    fi

    # Akamai
    if echo "$headers" | grep -qi "akamai"; then
        log_result "[*] CDN: Akamai detected"
        found_waf=1
    fi

    # AWS CloudFront
    if echo "$headers" | grep -qi "cloudfront\|x-amz-cf-id"; then
        log_result "[*] CDN: AWS CloudFront detected"
        found_waf=1
    fi

    # Incapsula
    if echo "$headers" | grep -qi "incapsula\|x-iinfo"; then
        log_result "[*] WAF: Incapsula detected"
        found_waf=1
    fi

    # Sucuri
    if echo "$headers" | grep -qi "sucuri"; then
        log_result "[*] WAF: Sucuri detected"
        found_waf=1
    fi

    # ModSecurity
    if echo "$headers" | grep -qi "mod_security\|NOYB"; then
        log_result "[*] WAF: ModSecurity detected"
        found_waf=1
    fi

    # Generic WAF detection via suspicious blocks
    local test_payload="${TARGET_URL}?test=<script>alert(1)</script>"
    local test_status=$(curl -s -o /dev/null -w "%{http_code}" -m $TIMEOUT "$test_payload" 2>/dev/null)

    if [ "$test_status" = "403" ] || [ "$test_status" = "406" ]; then
        log_result "[*] Possible WAF detected (blocks XSS test)"
        found_waf=1
    fi

    if [ $found_waf -eq 0 ]; then
        log_result "[*] No WAF/CDN detected"
    fi

    log_result ""
}

# 11. Technology Fingerprinting
scan_tech() {
    log_result "[+] TECHNOLOGY FINGERPRINTING"
    led_scanning

    LOG "Fingerprinting tech stack..."
    local headers=$(curl -s -I -m $TIMEOUT "$TARGET_URL" 2>/dev/null)
    # Get first 50KB of HTML (enough to catch WP indicators)
    local body=$(curl -s -m $TIMEOUT "$TARGET_URL" 2>/dev/null | head -c 50000)

    # Web servers
    local server=$(echo "$headers" | grep -i "^Server:" | cut -d':' -f2- | tr -d '\r' | sed 's/^ //')
    [ -n "$server" ] && log_result "[*] Web Server: $server"

    # PHP version
    if echo "$headers" | grep -qi "X-Powered-By.*PHP"; then
        local php_ver=$(echo "$headers" | grep -i "X-Powered-By" | grep -o "PHP/[0-9.]*" | tr -d '\r')
        log_result "[*] Backend: $php_ver"
    fi

    # WordPress Detection (multiple methods)
    local is_wordpress=0

    # Method 1: Check HTML for WordPress indicators
    if echo "$body" | grep -qi "wp-content\|wp-includes\|wp-json\|wordpress"; then
        is_wordpress=1
    fi

    # Method 2: Check headers for Pantheon (WordPress hosting)
    if echo "$headers" | grep -qi "pantheon\|x-pantheon"; then
        is_wordpress=1
        log_result "[*] Pantheon hosting detected (WordPress platform)"
    fi

    # Method 3: Test for wp-json API endpoint
    if [ $is_wordpress -eq 0 ]; then
        local wp_api_status=$(curl -s -o /dev/null -w "%{http_code}" -m $TIMEOUT "${TARGET_PROTO}://${TARGET_HOST}/wp-json/" 2>/dev/null)
        if [ "$wp_api_status" = "200" ]; then
            is_wordpress=1
        fi
    fi

    # Method 4: Test for wp-login.php
    if [ $is_wordpress -eq 0 ]; then
        local wp_login_status=$(curl -s -o /dev/null -w "%{http_code}" -m $TIMEOUT "${TARGET_PROTO}://${TARGET_HOST}/wp-login.php" 2>/dev/null)
        if [ "$wp_login_status" = "200" ]; then
            is_wordpress=1
        fi
    fi

    # If WordPress detected by any method, run tests
    if [ $is_wordpress -eq 1 ]; then
        log_result "[*] CMS: WordPress detected"

        # Try to get version
        local wp_ver=$(curl -s -m $TIMEOUT "${TARGET_PROTO}://${TARGET_HOST}/readme.html" 2>/dev/null | grep -i "Version" | head -1)
        [ -n "$wp_ver" ] && log_result "[*] $wp_ver"

        # WordPress-specific tests
        log_result "[*] Running WordPress tests..."

        # Test for user enumeration via REST API
        local wp_users=$(curl -s -m $TIMEOUT "${TARGET_PROTO}://${TARGET_HOST}/wp-json/wp/v2/users" 2>/dev/null)
        if echo "$wp_users" | grep -qi "slug\|name"; then
            log_result "[!] WP REST API user enumeration enabled!"
            play_found
            led_found
        fi

        # Test for user enumeration via ?author=1
        local author_page=$(curl -s -m $TIMEOUT "${TARGET_PROTO}://${TARGET_HOST}/?author=1" 2>/dev/null)
        if echo "$author_page" | grep -qiE "author/|posts by"; then
            log_result "[!] WP user enumeration via ?author=1"
            play_found
        fi

        # Test for xmlrpc
        local xmlrpc_status=$(curl -s -o /dev/null -w "%{http_code}" -m $TIMEOUT "${TARGET_PROTO}://${TARGET_HOST}/xmlrpc.php" 2>/dev/null)
        if [ "$xmlrpc_status" = "200" ]; then
            log_result "[!] xmlrpc.php accessible"
            play_found
        fi

        # Test for debug log
        local debug_status=$(curl -s -o /dev/null -w "%{http_code}" -m $TIMEOUT "${TARGET_PROTO}://${TARGET_HOST}/wp-content/debug.log" 2>/dev/null)
        if [ "$debug_status" = "200" ]; then
            log_result "[!] debug.log exposed!"
            play_found
            led_found
        fi

        # Test for wp-admin
        local admin_status=$(curl -s -o /dev/null -w "%{http_code}" -m $TIMEOUT "${TARGET_PROTO}://${TARGET_HOST}/wp-admin/" 2>/dev/null)
        if [ "$admin_status" = "200" ] || [ "$admin_status" = "302" ]; then
            log_result "[*] wp-admin accessible"
        fi

        # Test for wp-login.php
        local login_status=$(curl -s -o /dev/null -w "%{http_code}" -m $TIMEOUT "${TARGET_PROTO}://${TARGET_HOST}/wp-login.php" 2>/dev/null)
        if [ "$login_status" = "200" ]; then
            log_result "[*] wp-login.php accessible"
        fi
    fi

    # Drupal
    if echo "$body" | grep -qi "drupal"; then
        log_result "[*] CMS: Drupal detected"
    fi

    # Joomla
    if echo "$body" | grep -qi "joomla"; then
        log_result "[*] CMS: Joomla detected"
    fi

    # React
    if echo "$body" | grep -qi "react"; then
        log_result "[*] Frontend: React detected"
    fi

    # Vue.js
    if echo "$body" | grep -qi "vue\.js\|__vue__"; then
        log_result "[*] Frontend: Vue.js detected"
    fi

    # Angular
    if echo "$body" | grep -qi "ng-app\|angular"; then
        log_result "[*] Frontend: Angular detected"
    fi

    # jQuery
    if echo "$body" | grep -qi "jquery"; then
        local jquery_ver=$(echo "$body" | grep -o "jquery[/-][0-9.]*" | head -1 | tr -d '\r')
        [ -n "$jquery_ver" ] && log_result "[*] Library: $jquery_ver"
    fi

    log_result ""
}

# 12. Common Subdomain Checker
scan_subdomains() {
    log_result "[+] SUBDOMAIN ENUMERATION"
    led_scanning

    # Common subdomains to test
    local subdomains=(
        "www" "api" "admin" "dev" "staging" "test"
        "beta" "demo" "portal" "dashboard" "app" "mail"
        "ftp" "vpn" "ssh" "remote" "store" "shop"
        "blog" "forum" "status" "help" "support" "cdn"
        "static" "assets" "images" "media" "upload" "files"
        "mobile" "m" "secure" "login" "auth" "sso"
        "sandbox" "uat" "qa" "prod" "old" "new"
        "v2" "api2" "backend" "server" "db" "database"
        "cloud" "git" "gitlab" "jenkins" "monitor"
    )

    LOG "Testing ${#subdomains[@]} subdomains..."
    local found=0
    local tested=0
    local found_list=()

    for subdomain in "${subdomains[@]}"; do
        tested=$((tested + 1))

        # Progress indicator every 10 subdomains
        if [ $((tested % 10)) -eq 0 ]; then
            LOG "Tested $tested/${#subdomains[@]}..."
        fi

        local test_url="${TARGET_PROTO}://${subdomain}.${TARGET_HOST}"
        local status=$(curl -s -o /dev/null -w "%{http_code}" -m 3 "$test_url" 2>/dev/null)

        # Consider these status codes as "subdomain exists"
        case "$status" in
            200|301|302|303|307|308|401|403)
                log_result "[!] FOUND: ${subdomain}.${TARGET_HOST} [HTTP $status]"
                found=$((found + 1))
                found_list+=("${subdomain}")
                play_found
                led_found
                sleep 0.2
                ;;
            *)
                # Silent for 404, 000 (doesn't exist/timeout)
                ;;
        esac

        sleep 0.05
    done

    log_result ""
    if [ $found -eq 0 ]; then
        log_result "[*] No common subdomains found"
    else
        log_result "[*] SUMMARY: Found $found subdomain(s):"
        for sub in "${found_list[@]}"; do
            log_result "    - ${sub}.${TARGET_HOST}"
        done
    fi

    log_result ""
}

# 13. HTML Source Analysis
scan_html_source() {
    log_result "[+] HTML SOURCE ANALYSIS"
    led_scanning

    LOG "Analyzing HTML source..."
    local body=$(curl -s -m $TIMEOUT "$TARGET_URL" 2>/dev/null)
    local found=0

    # Extract HTML comments
    local comments=$(echo "$body" | grep -o '<!--.*-->' | head -10)
    if [ -n "$comments" ]; then
        log_result "[*] HTML Comments found:"
        while IFS= read -r comment; do
            # Clean up and shorten
            comment=$(echo "$comment" | sed 's/<!--//g; s/-->//g' | tr -d '\r' | head -c 100)
            [ -n "$comment" ] && log_result "    $comment"
            found=1
        done <<< "$comments"
    fi

    # Extract email addresses
    local emails=$(echo "$body" | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u | head -5)
    if [ -n "$emails" ]; then
        log_result "[!] Email addresses found:"
        while IFS= read -r email; do
            log_result "    $email"
            found=1
            play_found
        done <<< "$emails"
    fi

    # Look for API keys (common patterns)
    if echo "$body" | grep -qiE 'api[_-]?key|apikey|access[_-]?token|secret[_-]?key'; then
        log_result "[!] Possible API key references in source!"
        play_found
        led_found
        found=1
    fi

    # Look for internal URLs/paths
    local internal_urls=$(echo "$body" | grep -oE '(https?://[^"'"'"' >]+|/[a-zA-Z0-9/_-]+)' | grep -E '(internal|dev|staging|test|admin|api)' | sort -u | head -5)
    if [ -n "$internal_urls" ]; then
        log_result "[!] Internal URLs found:"
        while IFS= read -r url; do
            log_result "    $url"
            found=1
            play_found
        done <<< "$internal_urls"
    fi

    # Look for TODO/FIXME in HTML comments only (not in JS libraries)
    if echo "$comments" | grep -qiE 'TODO|FIXME|HACK|XXX|BUG'; then
        log_result "[!] Developer comments (TODO/FIXME) in HTML comments"
        # Show which ones were found
        local dev_comments=$(echo "$comments" | grep -iE 'TODO|FIXME|HACK|XXX|BUG' | head -3)
        while IFS= read -r comment; do
            [ -n "$comment" ] && log_result "    $(echo "$comment" | sed 's/<!--//g; s/-->//g' | tr -d '\r' | head -c 80)"
        done <<< "$dev_comments"
        found=1
        play_found
    fi

    # Look for stack traces or error messages (in visible HTML, not JS)
    # Only flag if we find actual stack traces, not just the word "error"
    if echo "$body" | grep -qiE '<pre.*stack|<div.*exception|Fatal error:|Uncaught|Notice:|Warning:.*line'; then
        log_result "[!] Possible stack trace/error in source"
        found=1
        play_found
    fi

    if [ $found -eq 0 ]; then
        log_result "[*] No interesting data in HTML source"
    fi

    log_result ""
}

# 14. Cloud Metadata Endpoints
scan_cloud_metadata() {
    log_result "[+] CLOUD METADATA ENDPOINTS"
    led_scanning

    LOG "Testing cloud metadata APIs..."
    local found=0

    # AWS Metadata
    log_result "[*] Testing AWS metadata..."
    local aws_meta="${TARGET_URL}?url=http://169.254.169.254/latest/meta-data/"
    local aws_status=$(curl -s -o /dev/null -w "%{http_code}" -m $TIMEOUT "$aws_meta" 2>/dev/null)
    if [ "$aws_status" = "200" ]; then
        log_result "[!!!] AWS metadata accessible (SSRF vulnerability)!"
        play_found
        led_found
        found=1
    fi

    # Try direct access (if on AWS)
    local aws_direct=$(curl -s -m 2 "http://169.254.169.254/latest/meta-data/" 2>/dev/null)
    if [ -n "$aws_direct" ]; then
        log_result "[!!!] Direct AWS metadata access!"
        play_found
        led_found
        found=1
    fi

    # GCP Metadata
    log_result "[*] Testing GCP metadata..."
    local gcp_meta="${TARGET_URL}?url=http://metadata.google.internal/computeMetadata/v1/"
    local gcp_status=$(curl -s -o /dev/null -w "%{http_code}" -m $TIMEOUT "$gcp_meta" 2>/dev/null)
    if [ "$gcp_status" = "200" ]; then
        log_result "[!!!] GCP metadata accessible (SSRF vulnerability)!"
        play_found
        led_found
        found=1
    fi

    # Azure Metadata
    log_result "[*] Testing Azure metadata..."
    local azure_meta="${TARGET_URL}?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    local azure_status=$(curl -s -o /dev/null -w "%{http_code}" -m $TIMEOUT "$azure_meta" 2>/dev/null)
    if [ "$azure_status" = "200" ]; then
        log_result "[!!!] Azure metadata accessible (SSRF vulnerability)!"
        play_found
        led_found
        found=1
    fi

    # Test common SSRF via file parameter
    local ssrf_params=("url" "file" "path" "redirect" "uri" "link" "src")
    for param in "${ssrf_params[@]}"; do
        local test_url="${TARGET_URL}?${param}=http://169.254.169.254/"
        local status=$(curl -s -o /dev/null -w "%{http_code}" -m $TIMEOUT "$test_url" 2>/dev/null)

        # If we get anything other than 404, might be SSRF
        if [ "$status" = "200" ] || [ "$status" = "500" ]; then
            log_result "[!] Possible SSRF via parameter: $param"
            play_found
            found=1
        fi
    done

    if [ $found -eq 0 ]; then
        log_result "[*] No cloud metadata exposure detected"
    fi

    log_result ""
}

# === MAIN MENU ===

show_menu() {
    PROMPT "=== CURLY SCANNER ===\n\nSelect scan mode:\n\n1. Quick Scan\n2. Full Scan (All Modules)\n3. API Recon\n4. Security Audit\n5. Tech Fingerprint\n6. Subdomain Enum"
}

# === MAIN ===

LOG "CURLY - Web Recon Scanner"
LOG "by curtthecoder"
LOG ""

# Get target URL from user
LOG "Please enter target URL..."
LOG "(e.g., example.com)"
TARGET_URL=$(TEXT_PICKER "Enter target URL" "example.com")

# Check if user cancelled or rejected
case $? in
    $DUCKYSCRIPT_CANCELLED)
        LOG "User cancelled"
        exit 1
        ;;
    $DUCKYSCRIPT_REJECTED)
        LOG "Dialog rejected"
        exit 1
        ;;
    $DUCKYSCRIPT_ERROR)
        LOG "An error occurred"
        exit 1
        ;;
esac

if [ -z "$TARGET_URL" ]; then
    LOG "No target provided!"
    exit 1
fi

# Ensure URL has protocol
if ! echo "$TARGET_URL" | grep -qE '^https?://'; then
    TARGET_URL="https://$TARGET_URL"
fi

parse_url "$TARGET_URL"
TARGET_URL="${TARGET_PROTO}://${TARGET_HOST}"

# Follow any redirects to get final destination (e.g., example.com -> www.example.com)
follow_redirects

init_loot

LOG ""
LOG "Target: $TARGET_URL"
LOG ""

# Menu selection
show_menu
SCAN_MODE=$(NUMBER_PICKER "Select scan mode" "1")

# Check if user cancelled
case $? in
    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
        LOG "Operation cancelled"
        exit 1
        ;;
esac

LOG ""
LOG "Starting scan mode $SCAN_MODE..."
play_scan

case $SCAN_MODE in
    1)  # Quick Scan
        scan_ip_geolocation
        scan_waf
        scan_tech
        scan_info
        scan_endpoints
        scan_html_source
        ;;
    2)  # Full Scan (All Modules)
        scan_ip_geolocation
        scan_waf
        scan_tech
        scan_subdomains
        scan_info
        scan_html_source
        scan_endpoints
        scan_backups
        scan_methods
        scan_headers
        scan_cookies
        scan_cors
        scan_redirects
        scan_cloud_metadata
        scan_api
        ;;
    3)  # API Recon
        scan_subdomains
        scan_endpoints
        scan_api
        ;;
    4)  # Security Audit
        scan_ip_geolocation
        scan_tech
        scan_info
        scan_html_source
        scan_methods
        scan_headers
        scan_cookies
        scan_cors
        scan_redirects
        scan_cloud_metadata
        ;;
    5)  # Tech Fingerprint
        scan_ip_geolocation
        scan_waf
        scan_tech
        scan_info
        ;;
    6)  # Subdomain Enumeration
        scan_subdomains
        ;;
    *)
        LOG "Invalid scan mode!"
        exit 1
        ;;
esac

led_success
play_complete
VIBRATE 50

LOG ""
LOG "Scan complete!"
LOG "Results: $LOOTFILE"
LOG ""
LOG "Check loot dir for details"
