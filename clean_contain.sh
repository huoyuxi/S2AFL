#!/bin/bash

# 如果有传入参数，则使用传入的参数；否则使用默认列表
if [ "$#" -gt 0 ]; then
    subjects=("$@")
else
    subjects=(
        lightftp bftpd proftpd pure-ftpd exim live555 kamailio forked-daapd lighttpd1
        proftpd-state-machines pure-ftpd-state-machines exim-state-machines
        live555-state-machines kamailio-state-machines forked-daapd-state-machines
    )
fi

# 遍历并清理容器和镜像
for subject in "${subjects[@]}"; do
    echo "Cleaning containers and image for: ${subject}"

    # 停止并删除基于该镜像的所有容器
    { docker ps -a -q --filter "ancestor=${subject}:latest" | xargs docker stop 2>/dev/null | xargs docker rm 2>/dev/null; } >/dev/null 2>&1
done

echo "Clean complete"