#!/bin/bash

export NUM_CONTAINERS="${NUM_CONTAINERS:-10}"
export TIMEOUT="${TIMEOUT:-86400}"
export SKIPCOUNT="${SKIPCOUNT:-1}"
export TEST_TIMEOUT="${TEST_TIMEOUT:-20000}"

export TARGET_LIST=$1
export FUZZER_LIST=$2

if [[ "x$TARGET_LIST" == "x" ]] || [[ "x$FUZZER_LIST" == "x" ]]
then
    echo "Usage: $0 TARGET FUZZER"
    exit 1
fi

if [[ "$FUZZER_LIST" != "aflnet" ]] && [[ "$FUZZER_LIST" != "all" ]]; then
    echo "Public release only retains benchmark automation for the aflnet container path." 1>&2
    echo "Use FUZZER=aflnet. The Python S2AFL workflow is released separately under ./python." 1>&2
    exit 1
fi

echo
echo "# NUM_CONTAINERS: ${NUM_CONTAINERS}"
echo "# TIMEOUT: ${TIMEOUT} s"
echo "# SKIPCOUNT: ${SKIPCOUNT}"
echo "# TEST TIMEOUT: ${TEST_TIMEOUT} ms"
echo "# TARGET LIST: ${TARGET_LIST}"
echo "# FUZZER LIST: aflnet"
echo

run_target() {
    local image=$1
    local result_dir=$2
    local out_dir=$3
    local options=$4

    cd "$PFBENCH"
    mkdir -p "$result_dir"
    profuzzbench_exec_common.sh "$image" "$NUM_CONTAINERS" "$result_dir" aflnet "$out_dir" "$options" "$TIMEOUT" "$SKIPCOUNT" &
}

for TARGET in $(echo $TARGET_LIST | sed "s/,/ /g")
do
    echo
    echo "***** RUNNING AFLNET ON $TARGET *****"
    echo

    case "$TARGET" in
        lightftp)
            run_target lightftp results-lightftp out-lightftp-aflnet "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+"
            ;;
        bftpd)
            run_target bftpd results-bftpd out-bftpd-aflnet "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+"
            ;;
        proftpd)
            run_target proftpd results-proftpd out-proftpd-aflnet "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+"
            ;;
        pure-ftpd)
            run_target pure-ftpd results-pure-ftpd out-pure-ftpd-aflnet "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+"
            ;;
        exim)
            run_target exim results-exim out-exim-aflnet "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+"
            ;;
        live555)
            run_target live555 results-live555 out-live555-aflnet "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none"
            ;;
        kamailio)
            run_target kamailio results-kamailio out-kamailio-aflnet "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+"
            ;;
        forked-daapd)
            run_target forked-daapd results-forked-daapd out-forked-daapd-aflnet "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+"
            ;;
        lighttpd1)
            run_target lighttpd1 results-lighttpd1 out-lighttpd1-aflnet "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+"
            ;;
        all)
            run_target lightftp results-lightftp out-lightftp-aflnet "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+"
            run_target bftpd results-bftpd out-bftpd-aflnet "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+"
            run_target proftpd results-proftpd out-proftpd-aflnet "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+"
            run_target pure-ftpd results-pure-ftpd out-pure-ftpd-aflnet "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+"
            run_target exim results-exim out-exim-aflnet "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+"
            run_target live555 results-live555 out-live555-aflnet "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none"
            run_target kamailio results-kamailio out-kamailio-aflnet "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+"
            run_target forked-daapd results-forked-daapd out-forked-daapd-aflnet "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+"
            run_target lighttpd1 results-lighttpd1 out-lighttpd1-aflnet "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+"
            ;;
        *)
            echo "Unsupported target: $TARGET" 1>&2
            exit 1
            ;;
    esac
done

wait
