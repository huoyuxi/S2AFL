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

echo
echo "# NUM_CONTAINERS: ${NUM_CONTAINERS}"
echo "# TIMEOUT: ${TIMEOUT} s"
echo "# SKIPCOUNT: ${SKIPCOUNT}"
echo "# TEST TIMEOUT: ${TEST_TIMEOUT} ms"
echo "# TARGET LIST: ${TARGET_LIST}"
echo "# FUZZER LIST: ${FUZZER_LIST}"
echo

for FUZZER in $(echo $FUZZER_LIST | sed "s/,/ /g")
do

    for TARGET in $(echo $TARGET_LIST | sed "s/,/ /g")
    do

        echo
        echo "***** RUNNING $FUZZER ON $TARGET *****"
        echo

##### FTP #####

        if [[ $TARGET == "lightftp" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            mkdir results-lightftp

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lightftp $NUM_CONTAINERS results-lightftp aflnet out-lightftp-aflnet "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lightftp $NUM_CONTAINERS results-lightftp s2afl out-lightftp-s2afl "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lightftp $NUM_CONTAINERS results-lightftp s2afl-s1 out-lightftp-s2afl_cl1 "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lightftp $NUM_CONTAINERS results-lightftp s2afl-s2 out-lightftp-s2afl_cl2 "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi


        if [[ $TARGET == "bftpd" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            mkdir results-bftpd

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh bftpd $NUM_CONTAINERS results-bftpd aflnet out-bftpd-aflnet "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh bftpd $NUM_CONTAINERS results-bftpd s2afl out-bftpd-s2afl "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi
            
            if [[ $FUZZER == "s2afl-s1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh bftpd $NUM_CONTAINERS results-bftpd s2afl-s1 out-bftpd-s2afl_cl1 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh bftpd $NUM_CONTAINERS results-bftpd s2afl-s2 out-bftpd-s2afl_cl2 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi


        if [[ $TARGET == "proftpd" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            mkdir results-proftpd

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh proftpd $NUM_CONTAINERS results-proftpd aflnet out-proftpd-aflnet "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh proftpd $NUM_CONTAINERS results-proftpd s2afl out-proftpd-s2afl "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh proftpd $NUM_CONTAINERS results-proftpd s2afl-s1 out-proftpd-s2afl_cl1 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh proftpd $NUM_CONTAINERS results-proftpd s2afl-s2 out-proftpd-s2afl_cl2 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

        if [[ $TARGET == "pure-ftpd" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            mkdir results-pure-ftpd

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh pure-ftpd $NUM_CONTAINERS results-pure-ftpd aflnet out-pure-ftpd-aflnet "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh pure-ftpd $NUM_CONTAINERS results-pure-ftpd s2afl out-pure-ftpd-s2afl "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh pure-ftpd $NUM_CONTAINERS results-pure-ftpd s2afl-s1 out-pure-ftpd-s2afl_cl1 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh pure-ftpd $NUM_CONTAINERS results-pure-ftpd s2afl-s2 out-pure-ftpd-s2afl_cl2 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi


##### SMTP #####

        if [[ $TARGET == "exim" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            mkdir results-exim

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh exim $NUM_CONTAINERS results-exim aflnet out-exim-aflnet "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh exim $NUM_CONTAINERS results-exim s2afl out-exim-s2afl "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh exim $NUM_CONTAINERS results-exim s2afl-s1 out-exim-s2afl_cl1 "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh exim $NUM_CONTAINERS results-exim s2afl-s2 out-exim-s2afl_cl2 "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi


##### RTSP #####

        if [[ $TARGET == "live555" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            mkdir results-live555

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh live555 $NUM_CONTAINERS results-live555 aflnet out-live555-aflnet "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh live555 $NUM_CONTAINERS results-live555 s2afl out-live555-s2afl "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh live555 $NUM_CONTAINERS results-live555 s2afl-s1 out-live555-s2afl_cl1 "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh live555 $NUM_CONTAINERS results-live555 s2afl-s2 out-live555-s2afl_cl2 "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none" $TIMEOUT $SKIPCOUNT &
            fi

        fi


##### SIP #####

        if [[ $TARGET == "kamailio" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            mkdir results-kamailio

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh kamailio $NUM_CONTAINERS results-kamailio aflnet out-kamailio-aflnet "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi
            
            if [[ $FUZZER == "s2afl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh kamailio $NUM_CONTAINERS results-kamailio s2afl out-kamailio-s2afl "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh kamailio $NUM_CONTAINERS results-kamailio s2afl-s1 out-kamailio-s2afl_cl1 "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh kamailio $NUM_CONTAINERS results-kamailio s2afl-s2 out-kamailio-s2afl_cl2 "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

##### DAAPD #####

        if [[ $TARGET == "forked-daapd" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            mkdir results-forked-daapd

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh forked-daapd $NUM_CONTAINERS results-forked-daapd aflnet out-forked-daapd-aflnet "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh forked-daapd $NUM_CONTAINERS results-forked-daapd s2afl out-forked-daapd-s2afl "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh forked-daapd $NUM_CONTAINERS results-forked-daapd s2afl-s1 out-forked-daapd-s2afl_cl1 "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh forked-daapd $NUM_CONTAINERS results-forked-daapd s2afl-s2 out-forked-daapd-s2afl_cl2 "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

##### HTTP #####

        if [[ $TARGET == "lighttpd1" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            mkdir results-lighttpd1

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lighttpd1 $NUM_CONTAINERS results-lighttpd1 aflnet out-lighttpd1-aflnet "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lighttpd1 $NUM_CONTAINERS results-lighttpd1 s2afl out-lighttpd1-s2afl "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lighttpd1 $NUM_CONTAINERS results-lighttpd1 s2afl-s1 out-lighttpd1-s2afl_cl1 "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "s2afl-s2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lighttpd1 $NUM_CONTAINERS results-lighttpd1 s2afl-s2 out-lighttpd1-s2afl_cl2 "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi


        if [[ $TARGET == "all" ]]
        then
            # Quit loop -- all fuzzers and targets have already been executed
            exit
        fi

    done
done

