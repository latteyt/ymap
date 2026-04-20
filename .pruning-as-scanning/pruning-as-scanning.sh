
check_file_exists() {
  if [[ ! -f "$1" ]]; then
    echo "Error: $1 not found" >&2
    exit 1
  fi
}

filter() {
  case $1 in
    32) str_len=9  ; suffix="::/32" ;;
    48) str_len=14 ; suffix="::/48" ;;
    56) str_len=17 ; suffix="00::/56" ;;
  esac

  awk -F, -v len="$str_len" -v suf="$suffix" '
  {
    prefix = substr($1, 1, len)
    if ($3 < 128 && prefix == substr($2, 1, len) && !seen[prefix]++) {
      printf("%s%s\n", prefix, suf)
    }
  }'
}

generate_ini_file() {
  case $1 in
    32) input="IANA.txt"; repeat=512 ;;
    48) input=".pruning-as-scanning/prefix32.txt" ; repeat=64 ;;
    56) input=".pruning-as-scanning/prefix48.txt" ; repeat=16 ;;
    64) input=".pruning-as-scanning/prefix56.txt" ; repeat=1 ;;
  esac

  cat <<EOF > ".pruning-as-scanning/scan$1.ini"
[Net]
L3Src   = $L3_SRC
L2Dst   = $L2_DST
IF      = $IF_NAME

[Runtime]
shard   = 2
rate    = 100000
repeat  = $repeat

seed    = 521
limit   = $1

[Scan]
type    = net
module  = icmpv6echo
input   = $input

iid     = rand
EOF
}

[[ -z "$IF_NAME" ]] && echo "Error: environment variable 'IF_NAME' is not set" >&2 && exit 1

L3_SRC=$(ip -6 addr show dev "$IF_NAME" | grep "inet6" | grep "global" |  awk '!seen[$2]++{print $2}' | cut -d'/' -f1)
L2_DST=$(ip -6 neigh show dev "$IF_NAME" | grep "router" | awk '!seen[$3]++{print $3}')

limits=(32 48 56 64)

# Ensure IANA.txt exists
check_file_exists "IANA.txt"

for i in "${!limits[@]}"; do
  limit="${limits[$i]}"
  generate_ini_file "$limit"
  sudo ./build/ymap ".pruning-as-scanning/scan${limit}.ini" > ".pruning-as-scanning/scan${limit}.txt"
  check_file_exists ".pruning-as-scanning/scan${limit}.txt"
  if [[ $limit != 64 ]]; then
    cat ".pruning-as-scanning/scan${limit}.txt" | filter $limit > ".pruning-as-scanning/prefix${limit}.txt"
    check_file_exists ".pruning-as-scanning/prefix${limit}.txt"
  fi
done
