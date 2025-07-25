#!/bin/bash
#
#--------------------------------------------------------------------------------------
#
# Author: Tony Carruthers
# Date: 23 July 2025
# Version: 1.4-Bravo
# Version 1.4 Bravo had an update that let the user inspect the Certificate
#--------------------------------------------------------------------------------------
#
# Interactive menu script to generate quantum‑safe certificates using the
# OpenQuantumSafe OQS provider in a Docker container.  It allows you to
# create a root CA, intermediate CAs signed by the root, and client
# certificates signed by an intermediate.  Subject fields and validity
# periods are collected interactively.

set -e

# Configuration
IMAGE="docker.io/openquantumsafe/oqs-ossl3"
ALGO="mldsa65"  # ML‑DSA‑65 (Dilithium 3)

# Find container runtime
DOCKER_BIN=$(command -v docker || command -v podman)
if [ -z "$DOCKER_BIN" ]; then
    echo "Error: neither docker nor podman was found in PATH. Please install one of them." >&2
    exit 1
fi

# Create a persistent working directory for certificates
WORKDIR="${PWD}/pq_certs_menu"
mkdir -p "$WORKDIR"

# Define relative subfolders for root, intermediates (multiple) and clients.
#
# We maintain both the absolute paths on the host (WORKDIR) and the
# relative paths inside the container.  The container mounts the entire
# WORKDIR at /work and uses that as its working directory, so we should
# reference files relative to /work when running OpenSSL commands in the
# container.  Using relative paths prevents errors like "Can't open
# /home/..." inside the container.
#
ROOT_RELDIR="root"
INTER_PARENT_RELDIR="intermediates"
CLIENTS_RELDIR="clients"

ROOT_DIR="$WORKDIR/$ROOT_RELDIR"
INTER_PARENT_DIR="$WORKDIR/$INTER_PARENT_RELDIR"
CLIENTS_DIR="$WORKDIR/$CLIENTS_RELDIR"

mkdir -p "$ROOT_DIR" "$INTER_PARENT_DIR" "$CLIENTS_DIR"

echo "Using container runtime: $DOCKER_BIN"
echo "Pulling image $IMAGE (if not already present)..."
$DOCKER_BIN pull "$IMAGE"

# Helper to run a command inside the container.  Accepts a command string
# (with embedded variables expanded by the host shell) and executes it
# within the container with /work mounted to $WORKDIR.
docker_exec() {
    local cmd="$1"
    $DOCKER_BIN run --rm \
        -v "$WORKDIR":/work \
        -w /work \
        "$IMAGE" /bin/sh -c "$cmd"
}

# Check for root CA files
have_root() {
    [ -f "$ROOT_DIR/root_ca.crt" ] && [ -f "$ROOT_DIR/root_ca.key" ]
}

# Check for at least one intermediate CA present
have_intermediate() {
    # Return success if there is at least one subdirectory in $INTER_PARENT_DIR
    [ -n "$(ls -A "$INTER_PARENT_DIR" 2>/dev/null)" ]
}

# List client certificate directories
list_clients() {
    local idx=1
    for dir in "$CLIENTS_DIR"/*/ ; do
        [ -d "$dir" ] || continue
        local name="${dir%/}"
        echo "$idx) ${name##*/}"
        idx=$((idx+1))
    done
}

# Prompt user to choose a client certificate directory
choose_client() {
    # Build list of client directories
    local client_dirs=()
    local display_names=()
    for dir in "$CLIENTS_DIR"/*/ ; do
        [ -d "$dir" ] || continue
        local abs_dir="${dir%/}"
        local rel_dir="${abs_dir#$WORKDIR/}"
        client_dirs+=("$rel_dir")
        display_names+=("${abs_dir##*/}")
    done
    if [ "${#client_dirs[@]}" -eq 0 ]; then
        echo "No client certificates found. Create a client first." >&2
        return 1
    fi
    echo "Available client certificates:"
    local i
    for i in "${!display_names[@]}"; do
        local num=$((i+1))
        echo "$num) ${display_names[$i]}"
    done
    read -p "Select a client by number: " client_choice
    if [[ ! "$client_choice" =~ ^[0-9]+$ ]] || [ "$client_choice" -lt 1 ] || [ "$client_choice" -gt "${#client_dirs[@]}" ]; then
        echo "Invalid selection." >&2
        return 1
    fi
    local index=$((client_choice-1))
    CHOSEN_CLIENT_RELDIR="${client_dirs[$index]}"
    CHOSEN_CLIENT_ABS_DIR="$WORKDIR/$CHOSEN_CLIENT_RELDIR"
    return 0
}

# Additional operations: regenerate chain or inspect CSR/certificate
additional_operations() {
    echo "Additional operations:"
    echo " 1) Regenerate concatenated certificate chain"
    echo " 2) Inspect CSR or certificate details"
    echo " 3) Return to main menu"
    read -p "Choose an option: " extra_choice
    case $extra_choice in
        1)
            regenerate_chain
            ;;
        2)
            inspect_pki_object
            ;;
        *)
            # Return to main menu on any other input
            return
            ;;
    esac
}

# Regenerate a concatenated certificate chain
regenerate_chain() {
    echo "Regenerate chain for:"
    echo " 1) Intermediate CA"
    echo " 2) Client certificate"
    read -p "Choose 1 or 2: " chain_type
    case $chain_type in
        1)
            # Choose intermediate
            if ! choose_intermediate; then
                return
            fi
            # Ask output filename
            read -p "Enter output filename for chain (relative to working dir, e.g., intermediate_chain.crt): " out_name
            # Determine relative output path
            local out_rel_path="$out_name"
            # Build command to concatenate intermediate + root (inside container).  We do not
            # echo the path inside the container; the message is printed outside.
            cmd="cat ${CHOSEN_INTER_RELDIR}/intermediate.crt ${ROOT_RELDIR}/root_ca.crt > ${out_rel_path}"
            docker_exec "$cmd"
            echo "Chain file created at ${WORKDIR}/${out_rel_path}"
            ;;
        2)
            # Choose client
            if ! choose_client; then
                return
            fi
            read -p "Enter output filename for chain (relative to working dir, e.g., client_chain.crt): " out_name
            local out_rel_path="$out_name"
            # For client, chain is client.crt + the existing client_chain (which already includes intermediate + root)
            cmd="cat ${CHOSEN_CLIENT_RELDIR}/client.crt ${CHOSEN_CLIENT_RELDIR}/client_chain.crt > ${out_rel_path}"
            docker_exec "$cmd"
            echo "Chain file created at ${WORKDIR}/${out_rel_path}"
            ;;
        *)
            echo "Invalid selection."
            ;;
    esac
}

# Inspect a CSR or certificate
inspect_pki_object() {
    echo "Inspect which type of file?"
    echo " 1) CSR (*.csr)"
    echo " 2) Certificate (*.crt)"
    read -p "Choose 1 or 2: " inspect_type
    case $inspect_type in
        1)
            # Gather list of CSR files
            local csr_files=()
            local display_csr=()
            # Search in root, intermediates and clients
            # root CA has no CSR saved
            # intermediate CSRs
            for dir in "$INTER_PARENT_DIR"/*/ ; do
                [ -d "$dir" ] || continue
                if [ -f "$dir/intermediate.csr" ]; then
                    local abs_file="$dir/intermediate.csr"
                    local rel_file="${abs_file#$WORKDIR/}"
                    csr_files+=("$rel_file")
                    display_csr+=("${rel_file}")
                fi
            done
            # client CSRs
            for dir in "$CLIENTS_DIR"/*/ ; do
                [ -d "$dir" ] || continue
                if [ -f "$dir/client.csr" ]; then
                    local abs_file="$dir/client.csr"
                    local rel_file="${abs_file#$WORKDIR/}"
                    csr_files+=("$rel_file")
                    display_csr+=("${rel_file}")
                fi
            done
            if [ "${#csr_files[@]}" -eq 0 ]; then
                echo "No CSR files found." >&2
                return
            fi
            echo "Available CSR files:";
            local i
            for i in "${!display_csr[@]}"; do
                local num=$((i+1))
                echo "$num) ${display_csr[$i]}"
            done
            read -p "Select a CSR by number: " csr_choice
            if [[ ! "$csr_choice" =~ ^[0-9]+$ ]] || [ "$csr_choice" -lt 1 ] || [ "$csr_choice" -gt "${#csr_files[@]}" ]; then
                echo "Invalid selection." >&2
                return
            fi
            local index=$((csr_choice-1))
            local csr_rel_path="${csr_files[$index]}"
            # Inspect CSR using openssl req -text -noout
            # According to the Lindevs tutorial, openssl req -in CSR.csr -text -noout decodes CSR information【82771930933432†L103-L115】.
            cmd="set -e; \
            openssl req -provider default -provider oqsprovider \
              -in ${csr_rel_path} -text -noout"
            docker_exec "$cmd"
            ;;
        2)
            # Gather list of certificate files
            local crt_files=()
            local display_crt=()
            # root certificate
            if [ -f "$ROOT_DIR/root_ca.crt" ]; then
                local abs_file="$ROOT_DIR/root_ca.crt"
                local rel_file="${abs_file#$WORKDIR/}"
                crt_files+=("$rel_file")
                display_crt+=("${rel_file}")
            fi
            # intermediate certificates
            for dir in "$INTER_PARENT_DIR"/*/ ; do
                [ -d "$dir" ] || continue
                if [ -f "$dir/intermediate.crt" ]; then
                    local abs_file="$dir/intermediate.crt"
                    local rel_file="${abs_file#$WORKDIR/}"
                    crt_files+=("$rel_file")
                    display_crt+=("${rel_file}")
                fi
                # also include intermediate_chain
                if [ -f "$dir/intermediate_chain.crt" ]; then
                    local abs_file2="$dir/intermediate_chain.crt"
                    local rel_file2="${abs_file2#$WORKDIR/}"
                    crt_files+=("$rel_file2")
                    display_crt+=("${rel_file2}")
                fi
            done
            # client certificates and chains
            for dir in "$CLIENTS_DIR"/*/ ; do
                [ -d "$dir" ] || continue
                if [ -f "$dir/client.crt" ]; then
                    local abs_file="$dir/client.crt"
                    local rel_file="${abs_file#$WORKDIR/}"
                    crt_files+=("$rel_file")
                    display_crt+=("${rel_file}")
                fi
                if [ -f "$dir/client_chain.crt" ]; then
                    local abs_file2="$dir/client_chain.crt"
                    local rel_file2="${abs_file2#$WORKDIR/}"
                    crt_files+=("$rel_file2")
                    display_crt+=("${rel_file2}")
                fi
            done
            if [ "${#crt_files[@]}" -eq 0 ]; then
                echo "No certificate files found." >&2
                return
            fi
            echo "Available certificate files:"
            local i
            for i in "${!display_crt[@]}"; do
                local num=$((i+1))
                echo "$num) ${display_crt[$i]}"
            done
            read -p "Select a certificate by number: " crt_choice
            if [[ ! "$crt_choice" =~ ^[0-9]+$ ]] || [ "$crt_choice" -lt 1 ] || [ "$crt_choice" -gt "${#crt_files[@]}" ]; then
                echo "Invalid selection." >&2
                return
            fi
            local index=$((crt_choice-1))
            local crt_rel_path="${crt_files[$index]}"
            # Inspect certificate using openssl x509 -text -noout
            cmd="set -e; \
            openssl x509 -provider default -provider oqsprovider \
              -in ${crt_rel_path} -text -noout"
            docker_exec "$cmd"
            ;;
        *)
            echo "Invalid selection."
            ;;
    esac
}

# List intermediate CA directories
list_intermediates() {
    # Print a numbered list of intermediate directories to stdout.  The
    # underlying list is built by choose_intermediate; this helper simply
    # shows the options.
    local idx=1
    for dir in "$INTER_PARENT_DIR"/*/ ; do
        [ -d "$dir" ] || continue
        local name="${dir%/}"
        echo "$idx) ${name##*/}"
        idx=$((idx+1))
    done
}

# Prompt user to choose an intermediate CA and set global variables for paths
choose_intermediate() {
    if ! have_intermediate; then
        echo "No intermediate CAs found in $INTER_PARENT_DIR. Create an intermediate CA first." >&2
        return 1
    fi
    echo "Available intermediate CAs:"
    # Build array of relative directories for intermediate CAs
    local inter_dirs=()
    local display_names=()
    for dir in "$INTER_PARENT_DIR"/*/ ; do
        [ -d "$dir" ] || continue
        # Derive relative path by stripping WORKDIR prefix and trailing slash
        local abs_dir="${dir%/}"
        local rel_dir="${abs_dir#$WORKDIR/}"
        inter_dirs+=("$rel_dir")
        display_names+=("${abs_dir##*/}")
    done
    # Display numbered list
    local i
    for i in "${!display_names[@]}"; do
        local num=$((i+1))
        echo "$num) ${display_names[$i]}"
    done
    read -p "Select an intermediate CA by number: " int_choice
    # Validate selection
    if [[ ! "$int_choice" =~ ^[0-9]+$ ]] || [ "$int_choice" -lt 1 ] || [ "$int_choice" -gt "${#inter_dirs[@]}" ]; then
        echo "Invalid selection." >&2
        return 1
    fi
    local index=$((int_choice-1))
    CHOSEN_INTER_RELDIR="${inter_dirs[$index]}"
    CHOSEN_INTER_ABS_DIR="$WORKDIR/$CHOSEN_INTER_RELDIR"
    return 0
}

# Create a new root CA (overwrites existing files)
create_root() {
    echo "Creating a new root CA"
    read -p "  Common Name (CN) for the root CA: " root_cn
    read -p "  Organisation (O) for the root CA: " root_o
    read -p "  Validity period (days) for the root CA: " root_days
    
    # Ensure the root directory exists on the host
    mkdir -p "$ROOT_DIR"
    # Use relative paths inside the container to avoid absolute host paths
    local root_rel_key="${ROOT_RELDIR}/root_ca.key"
    local root_rel_crt="${ROOT_RELDIR}/root_ca.crt"
    cmd="set -e; \
    openssl req -provider default -provider oqsprovider \
      -x509 -new -newkey $ALGO -nodes \
      -keyout ${root_rel_key} -out ${root_rel_crt} \
      -subj \"/CN=${root_cn}/O=${root_o}\" \
      -days ${root_days}"
    docker_exec "$cmd"
    echo "Root CA generated in ${ROOT_DIR}"
}

# Create a new intermediate CA signed by the root
create_intermediate() {
    if ! have_root; then
        echo "Root CA not found in $ROOT_DIR. Create the root CA first." >&2
        return
    fi
    echo "Creating a new intermediate CA signed by the root"
    read -p "  Common Name (CN) for the intermediate CA: " int_cn
    read -p "  Organisation (O) for the intermediate CA: " int_o
    read -p "  Validity period (days) for the intermediate CA: " int_days

    # Sanitize CN for directory name
    local safe_cn=$(echo "$int_cn" | tr ' ' '_' | tr -cd '[:alnum:]_')
    local timestamp=$(date +%Y%m%d_%H%M%S)
    # Determine relative and absolute directories for this intermediate
    local new_inter_rel_dir="${INTER_PARENT_RELDIR}/${safe_cn}_${timestamp}"
    local new_inter_abs_dir="$WORKDIR/${new_inter_rel_dir}"
    mkdir -p "$new_inter_abs_dir"

    # Relative paths inside the container
    local inter_rel_key="${new_inter_rel_dir}/intermediate.key"
    local inter_rel_csr="${new_inter_rel_dir}/intermediate.csr"
    local inter_rel_crt="${new_inter_rel_dir}/intermediate.crt"
    local inter_rel_chain="${new_inter_rel_dir}/intermediate_chain.crt"

    # Root relative paths for signing
    local root_rel_crt="${ROOT_RELDIR}/root_ca.crt"
    local root_rel_key="${ROOT_RELDIR}/root_ca.key"

    cmd="set -e; \
    # Generate key and CSR for intermediate
    openssl req -provider default -provider oqsprovider \
      -new -newkey $ALGO -nodes \
      -keyout ${inter_rel_key} -out ${inter_rel_csr} \
      -subj \"/CN=${int_cn}/O=${int_o}\"; \
    # Sign CSR with root CA
    openssl x509 -provider default -provider oqsprovider \
      -req -in ${inter_rel_csr} \
      -CA ${root_rel_crt} -CAkey ${root_rel_key} \
      -CAcreateserial \
      -out ${inter_rel_crt} \
      -days ${int_days}; \
    # Build intermediate chain (intermediate + root)
    cat ${inter_rel_crt} ${root_rel_crt} > ${inter_rel_chain}"
    docker_exec "$cmd"
    echo "Intermediate CA generated in ${new_inter_abs_dir}"
}

# Create a new client certificate signed by the current intermediate
create_client() {
    if ! have_intermediate; then
        echo "No intermediate CAs available. Create an intermediate CA first." >&2
        return
    fi
    # Prompt user to choose the intermediate CA to sign this client
    if ! choose_intermediate; then
        return
    fi
    # Extract just the base directory name for display
    local inter_base="${CHOSEN_INTER_ABS_DIR##*/}"
    echo "Creating a new client certificate signed by the intermediate ${inter_base}"
    read -p "  Common Name (CN) for the client: " client_cn
    read -p "  Organisation (O) for the client: " client_o
    read -p "  Validity period (days) for the client certificate: " client_days

    # Sanitize CN for directory name (replace spaces with underscores and remove other non-alphanumerics)
    safe_cn=$(echo "$client_cn" | tr ' ' '_' | tr -cd '[:alnum:]_')
    timestamp=$(date +%Y%m%d_%H%M%S)
    # Determine relative and absolute paths for client directory
    local client_rel_dir="${CLIENTS_RELDIR}/${safe_cn}_${timestamp}"
    local client_abs_dir="$WORKDIR/${client_rel_dir}"
    mkdir -p "$client_abs_dir"
    client_key="${client_rel_dir}/client.key"
    client_csr="${client_rel_dir}/client.csr"
    client_crt="${client_rel_dir}/client.crt"
    client_chain="${client_rel_dir}/client_chain.crt"

    # Set relative paths to chosen intermediate chain, certificate and key
    local chosen_inter_crt="${CHOSEN_INTER_RELDIR}/intermediate.crt"
    local chosen_inter_key="${CHOSEN_INTER_RELDIR}/intermediate.key"
    local chosen_inter_chain="${CHOSEN_INTER_RELDIR}/intermediate_chain.crt"

    cmd="set -e; \
    # Generate key and CSR for client
    openssl req -provider default -provider oqsprovider \
      -new -newkey $ALGO -nodes \
      -keyout ${client_key} -out ${client_csr} \
      -subj \"/CN=${client_cn}/O=${client_o}\"; \
    # Sign CSR with selected intermediate CA
    openssl x509 -provider default -provider oqsprovider \
      -req -in ${client_csr} \
      -CA ${chosen_inter_crt} -CAkey ${chosen_inter_key} \
      -CAcreateserial \
      -out ${client_crt} \
      -days ${client_days}; \
    # Create full chain (client + intermediate chain)
    cat ${client_crt} ${chosen_inter_chain} > ${client_chain}"
    docker_exec "$cmd"
    echo "Client certificate generated in ${client_abs_dir}. Full chain: ${client_chain}"
}

# Menu loop
while true; do
    echo "\n=== Quantum‑Safe Certificate Generator Menu ==="
    echo "1) Create or overwrite root CA"
    echo "2) Create intermediate CA signed by root"
    echo "3) Create client certificate signed by intermediate"
    echo "4) Exit"
    echo "5) Additional operations (regenerate chain or inspect CSR/certificate)"
    read -p "Choose an option: " choice
    case $choice in
        1)
            create_root
            ;;
        2)
            create_intermediate
            ;;
        3)
            create_client
            ;;
        4)
            echo "Exiting. Certificates are stored in $WORKDIR"
            break
            ;;
        5)
            additional_operations
            ;;
        *)
            echo "Invalid option. Please choose 1‑5."
            ;;
    esac
done