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
      print prefix, suf
    }
  }'
}

check_file_exists() {
  if [[ ! -f "$1" ]]; then
    echo "Error: $1 not found" >&2
    exit 1
  fi
}

# 生成 .ini 文件模板
generate_ini_file() {
  local limit=$1
  local input=$2

  cat <<EOF > ".pruning-as-scanning/scan${limit}.ini"
[Net]
L3Src   = $L3_SRC
L2Dst   = $L2_DST
IF      = $IF_NAME

[Runtime]
shard   = 2
rate    = 100000
repeat  = 512

seed    = 521
limit   = $limit

[Scan]
type    = net
module  = icmpv6echo
input   = $input

iid     = rand
EOF
}

[[ -z "$IF_NAME" ]] && echo "Error: environment variable 'IF_NAME' is not set" >&2 && exit 1

L3_SRC=$(ip -6 addr show dev "$IF_NAME" | grep "inet6" | grep "global" | awk '{print $2}' | cut -d'/' -f1)
L2_DST=$(ip -6 neigh show dev "$IF_NAME" | grep "router" | awk '{print $3}')

limits=(32 48 56 64)
inputs=("IANA.txt" ".pruning-as-scanning/prefix32.txt" ".pruning-as-scanning/prefix48.txt" ".pruning-as-scanning/prefix56.txt")

# Ensure IANA.txt exists
check_file_exists "IANA.txt"

for i in "${!limits[@]}"; do
  limit="${limits[$i]}"
  input="${inputs[$i]}"
  generate_ini_file "$limit" "$input"
  sudo ./build/ymap ".pruning-as-scanning/scan${limit}.ini" > ".pruning-as-scanning/scan${limit}.txt"
  check_file_exists ".pruning-as-scanning/scan${limit}.txt"
  if [[ $limit != 64 ]]; then
    cat ".pruning-as-scanning/scan${limit}.txt" | filter $limit > ".pruning-as-scanning/prefix${limit}.txt"
    check_file_exists ".pruning-as-scanning/prefix${limit}.txt"
  fi
done
