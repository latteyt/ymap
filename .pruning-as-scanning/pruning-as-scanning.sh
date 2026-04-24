
[[ -z "$IF_NAME" ]] && echo "Error: environment variable 'IF_NAME' is not set" >&2 && exit 1

SCAN_RATE="${SCAN_RATE:-100000}"
if [[ ! "$SCAN_RATE" =~ ^[0-9]+$ ]] || [[ "$SCAN_RATE" -le 0 ]]; then
  echo "Error: environment variable 'SCAN_RATE' must be a positive integer" >&2
  exit 1
fi

SHARD="${SHARD:-2}"
if [[ ! "$SHARD" =~ ^[0-9]+$ ]] || [[ "$SHARD" -le 0 ]]; then
  echo "Error: environment variable 'SHARD' must be a positive integer" >&2
  exit 1
fi

if [[ -v SEED ]]; then
  if [[ ! "$SEED" =~ ^[0-9]+$ ]]; then
    echo "Error: environment variable 'SEED' must be an integer" >&2
    exit 1
  fi
fi

check_file_exists() {
  if [[ ! -f "$1" ]]; then
    echo "Error: $1 not found" >&2
    exit 1
  fi
}

extract() {
  case $1 in
    32) str_len=9  ; suffix="::/32" ;;
    48) str_len=14 ; suffix="::/48" ;;
    56) str_len=17 ; suffix="00::/56" ;;
    *) echo "Error: invalid limit '$1' in filter" >&2; exit 1 ;;
  esac

  awk -F, -v len="$str_len" -v suf="$suffix" '!seen[(p=substr($1,1,len))]++{print p suf}'
}



# Generate a scan config for the current prefix length.
# Each round scans one prefix size and feeds its output into the next round.
generate_ini_file() {
  case $1 in
    32) input="IANA.txt"; repeat=256 ;;
    48) input=".pruning-as-scanning/prefix32.txt" ; repeat=16 ;;
    56) input=".pruning-as-scanning/prefix48.txt" ; repeat=4 ;;
    64) input=".pruning-as-scanning/prefix56.txt" ; repeat=1 ;;
    *) echo "Error: invalid limit '$1' in generate_ini_file" >&2; exit 1 ;;
  esac

  cat <<EOF > ".pruning-as-scanning/scan$1.ini"
[Interface]
name    = $IF_NAME
l2_dst  = $L2_DST
l3_src  = $L3_SRC

[Runtime]
shard   = $SHARD
rate    = $SCAN_RATE
repeat  = $repeat

[Scan]
type    = net
module  = icmp6_echo
input   = $input

[Optional]
$( [[ -v SEED ]] && echo "seed    = $SEED" )
limit   = $1
iid     = rand
EOF
}


L3_SRC=$(ip -6 addr show dev "$IF_NAME" | grep "inet6" | grep "global" |  "$AWK_BIN" '!seen[$2]++{print $2}' | cut -d'/' -f1)
L2_DST=$(ip -6 neigh show dev "$IF_NAME" | grep "router" | "$AWK_BIN" '!seen[$3]++{print $3}')

limits=(32 48 56 64)

# Round 0 input is the global IPv6 allocation list used to seed the first scan.
check_file_exists "IANA.txt"

# Scan from shorter prefixes to longer prefixes, pruning redundant space after
# each round before generating the next round's input list.
for i in "${!limits[@]}"; do
  limit="${limits[$i]}"
  generate_ini_file "$limit"
  # Keep only prefixes whose responses share the same prefix fingerprint.
  # This is the pruning step that decides which prefixes should be explored deeper.
  # `filter` checks whether the discovered periphery and the target address
  # belong to the same IPv6 prefix. Since IPv6 forwarding is prefix-based,
  # this helps decide whether the prefix should be explored further.
  sudo ./build/ymap ".pruning-as-scanning/scan${limit}.ini" | awk -F, -v len="${limit}" '$3<128&&$2>=len{print $1}' > ".pruning-as-scanning/scan${limit}.txt"
  check_file_exists ".pruning-as-scanning/scan${limit}.txt"
  if [[ $limit != 64 ]]; then
    cat ".pruning-as-scanning/scan${limit}.txt" | extract $limit > ".pruning-as-scanning/prefix${limit}.txt"
    check_file_exists ".pruning-as-scanning/prefix${limit}.txt"
  fi
done
